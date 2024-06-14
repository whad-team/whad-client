from prompt_toolkit import print_formatted_text, HTML
from scapy.all import Packet

def success(message):
    """Display a success message in green (if color is enabled)
    """
    print_formatted_text(HTML('<aaa fg="#027923"><b>%s</b></aaa>' % message))

def warning(message):
    """Display a warning message in orange (if color is enabled)
    """
    print_formatted_text(HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % message))

def error(message):
    """Display an error message in red (if color is enabled)
    """
    print_formatted_text(HTML('<ansired>[!] <b>%s</b></ansired>' % message))

def info(message):
    """Display an error info message in cyan (if color is enabled)
    """
    print_formatted_text(HTML('<ansicyan>[!] <b>%s</b></ansicyan>' % message))


def display_packet(pkt, show_metadata=True, format='repr'):
    """
    Display an packet according to the selected format.

    Four main types of formats can be used:
        * repr: scapy packet repr method (default)
        * show: scapy show method, "field" representation
        * hexdump: hexdump representation of the packet content
        * raw: raw received bytes

    :param  pkt:        Received Signal Strength Indicator
    :type   pkt:        :class:`scapy.packet.packet`
    """
    if isinstance(pkt, Packet):

        metadata = ""
        if hasattr(pkt, "metadata") and show_metadata:
            metadata = repr(pkt.metadata)

        # Process scapy show method format
        if format == "show":
            print_formatted_text(
                HTML(
                    '<b><ansipurple>%s</ansipurple></b>' % (
                        metadata
                    )
                )
            )
            pkt.show()

            if hasattr(pkt, "decrypted"):
                print_formatted_text(
                    HTML(
                        "<ansicyan>[i] Decrypted payload:</ansicyan>"
                    )
                )
                pkt.decrypted.show()

        # Process raw bytes format
        elif format == "raw":
            print_formatted_text(
                HTML(
                    '<b><ansipurple>%s</ansipurple></b> %s' % (
                        metadata,
                        bytes(pkt).hex()
                    )
                )
            )

            if hasattr(pkt, "decrypted"):
                print_formatted_text(
                    HTML(
                        "<ansicyan>[i] Decrypted payload:</ansicyan> %s" %
                        bytes(pkt.decrypted).hex()
                    )
                )

        # Process hexdump format
        elif format == "hexdump":
            print_formatted_text(
                HTML(
                    '<b><ansipurple>%s</ansipurple></b>' % (
                        metadata
                    )
                )
            )
            print_formatted_text(
                HTML("<i>%s</i>" %
                    escape(hexdump(bytes(pkt), result="return"))
                )
            )
            if hasattr(pkt, "decrypted"):
                print_formatted_text(
                    HTML(
                        "<ansicyan>[i] Decrypted payload:</ansicyan>"
                    )
                )
                print_formatted_text(
                        HTML("<i>%s</i>" %
                            escape(hexdump(bytes(pkt.decrypted), result="return")
                        )
                    )
                )
        # Process scapy repr format
        else:
            print_formatted_text(
                HTML(
                    '<b><ansipurple>%s</ansipurple></b>' % (
                        metadata
                    )
                )
            )
            print(repr(pkt))
            if hasattr(pkt, "decrypted"):
                print_formatted_text(
                    HTML("<ansicyan>[i] Decrypted payload:</ansicyan>")
                )
                print(repr(pkt.decrypted))
        print()
    # If it is not a packet, use repr method
    else:
        print(repr(pkt))

def display_event(event):
    """Display an event generated from a sniffer.
    """
    print_formatted_text(
        HTML(
            "<ansicyan>[i] event: <b>%s</b></ansicyan> %s" % (
                event.name,
                "("+event.message +")" if event.message is not None else ""
            )
        )
    )