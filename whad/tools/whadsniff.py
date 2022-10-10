from pkgutil import iter_modules
from importlib import import_module
from argparse import ArgumentParser
from dataclasses import fields, is_dataclass
from inspect import getdoc
import sys

import whad
from whad.device import WhadDevice
from whad.common.monitors import PcapWriterMonitor, WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, UnsupportedDomain, UnsupportedCapability

def list_implemented_environment():
    environment = {}

    for _, candidate_protocol,_ in iter_modules(whad.__path__):
        try:
            module = import_module("whad.{}.connector.sniffer".format(candidate_protocol))
            configuration_module = import_module("whad.{}.sniffing".format(candidate_protocol))
            environment[candidate_protocol] = {"sniffer_class":module.Sniffer, "configuration_class":configuration_module.SnifferConfiguration}
        except ModuleNotFoundError:
            pass
    return environment

def get_sniffer_parameters(configuration_class):
    parameters = {}
    configuration_documentation = {
                i.replace(":param ","").split(":")[0] : i.replace(":param ","").split(":")[1]
                for i in getdoc(configuration_class).split("\n")
                if i.startswith(":param ")
    }

    for field in fields(configuration_class):
        if is_dataclass(field.type):
            subfield_configuration_documentation = {
                        i.replace(":param ","").split(":")[0] : i.replace(":param ","").split(":")[1]
                        for i in getdoc(field.type).split("\n")
                        if i.startswith(":param ")
            }
            for subfield in fields(field.type):
                parameters["{}.{}".format(field.name,subfield.name)] = (subfield.type, subfield.default, field.type, subfield_configuration_documentation[subfield.name] if subfield.name in subfield_configuration_documentation else None)
        else:
            parameters[field.name] = (field.type, field.default, None, configuration_documentation[field.name] if field.name in configuration_documentation else None)
    return parameters

def build_arguments(environment):
    parser = ArgumentParser()
    parser.add_argument(
        'device',
        metavar='DEVICE',
        type=str,
        help='WHAD device'
    )
    parser.add_argument(
        '--show',
        dest='show',
        action="store_true",
        help='Display packets using scapy show method'
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        default=None,
        type=str,
        help='Output PCAP file'
    )

    parser.add_argument(
        '-w',
        '--wireshark',
        dest='wireshark',
        action='store_true',
        help='Enable wireshark monitoring'
    )

    parser.add_argument(
        '--raw',
        dest='raw',
        action="store_true",
        help='Display raw packets (hexadecimal)'
    )

    parser.add_argument(
        '--hide_metadata',
        dest='metadata',
        action="store_false",
        help='Hide packets metadata'
    )

    subparsers = parser.add_subparsers(
        required=True,
        dest="protocol",
        help='Protocol in use'
    )

    for protocol_name in environment:
        environment[protocol_name]["subparser"] = subparsers.add_parser(protocol_name)
        for parameter_name, (parameter_type, parameter_default, parameter_base_class, parameter_help) in environment[protocol_name]["parameters"].items():

            dest = parameter_name
            if parameter_base_class is not None:
                parameter_base, parameter_name = parameter_name.split(".")
            if parameter_help is not None and "(" in parameter_help:
                parameter_shortnames = ["-{}".format(i) for i in parameter_help.split("(")[1].replace(")","").split(",")]
                parameter_help = parameter_help.split("(")[0]
            else:
                parameter_shortnames = []
            if parameter_type != bool:
                if parameter_type == int:
                    def auto_int(x):
                        return int(x, 0)
                    parameter_type = auto_int # allow to provide hex arguments

                if parameter_type == list:
                    parameter_default=[]
                    parameter_type=str
                    action = "append"
                else:
                    action = "store"
                environment[protocol_name]["subparser"].add_argument(
                    "--"+parameter_name,
                    *parameter_shortnames,
                    default=parameter_default,
                    action=action,
                    type=parameter_type,
                    dest=dest,
                    help=parameter_help
                )
            else:
                environment[protocol_name]["subparser"].add_argument(
                    "--"+parameter_name,
                    *parameter_shortnames,
                    action='store_true',
                    dest=dest,
                    help=parameter_help
                )
    return parser

def build_configuration_from_args(environment, args):
    configuration = environment[args.protocol]["configuration_class"]()
    subfields = {}
    for parameter in environment[args.protocol]["parameters"]:
        base_class = None

        base_class = environment[args.protocol]["parameters"][parameter][2]

        if base_class is None:
            setattr(configuration,parameter,getattr(args,parameter))
        else:
            main, sub = parameter.split(".")
            if main not in subfields:
                subfields[main] = base_class()
            setattr(subfields[main], sub, getattr(args, parameter))


    for subfield in subfields:
        create = False
        for item in fields(subfields[subfield]):
            if getattr(subfields[subfield], item.name) is not None:
                create = True
                break
        if create:
            setattr(configuration, subfield, subfields[subfield])
        else:
            setattr(configuration, subfield, None)
    return configuration

def display(pkt, args):
    metadata = ""
    if hasattr(pkt, "metadata") and args.metadata:
        metadata = repr(pkt.metadata)
    if args.show:
        print(metadata)
        pkt.show()
        if hasattr(pkt, "decrypted"):
            print("[i] Decrypted payload:")
            pkt.decrypted.show()
    elif args.raw:
        print(metadata, bytes(pkt).hex())
        if hasattr(pkt, "decrypted"):
            print("[i] Decrypted payload:", bytes(pkt.decrypted).hex())
    else:
        print(metadata, repr(pkt))
        if hasattr(pkt, "decrypted"):
            print("[i] Decrypted payload:", repr(pkt.decrypted))
    print()

def main():
    environment = list_implemented_environment()
    for protocol_name in environment:
        environment[protocol_name]["parameters"] = get_sniffer_parameters(environment[protocol_name]["configuration_class"])

    parser = build_arguments(environment)
    args = parser.parse_args()
    configuration = build_configuration_from_args(environment, args)
    sniffer = None

    monitors = []

    try:
        dev = WhadDevice.create(args.device)
        sniffer = environment[args.protocol]["sniffer_class"](dev)

        if args.output is not None:
            monitor_pcap = PcapWriterMonitor(args.output)
            monitor_pcap.attach(sniffer)
            monitor_pcap.start()
            monitors.append(monitor_pcap)

        if args.wireshark:
            monitor_wireshark = WiresharkMonitor()
            monitor_wireshark.attach(sniffer)
            monitor_wireshark.start()
            monitors.append(monitor_wireshark)


        sniffer.configuration = configuration
        sniffer.start()

        for pkt in sniffer.sniff():
            display(pkt, args)

    except WhadDeviceNotFound as dev_error:
        # Device not found, display error and return -1
        print('[!] WHAD device not found (are you sure `%s` is a valid device identifier ?)' % (
            args.device
        ))
        sys.exit(-1)

    except WhadDeviceNotReady as dev_busy:
        # Device not ready, display error and return -1
        print('[!] WHAD device seems busy, make sure no other program is using it.')
        sys.exit(-1)

    except UnsupportedDomain as unsupported_domain:
        print('[!] WHAD device doesn\'t support selected protocol ({})'.format(args.protocol))
        sys.exit(-1)

    except UnsupportedCapability as unsupported_capability:
        print('[!] WHAD device doesn\'t support selected capability ({})'.format(unsupported_capability.capability))
        sys.exit(-1)

    except KeyboardInterrupt as keybd_evt:
        if sniffer is not None:
            sys.stdout.write('Stopping sniffer ...')
            sys.stdout.flush()
            sniffer.stop()
            sniffer.close()
            sys.stdout.write(' done\n')
            sys.stdout.flush()
        for monitor in monitors:
            monitor.close()

if __name__ == '__main__':
    main()
