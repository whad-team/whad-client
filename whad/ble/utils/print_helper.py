

def print_data_and_hex(data, is_handle_in_data, prefix=""):
    """Print supplied data followed by the hexadecimal equivalent

    :param data: List of data strings to be printed or string
    :param is_handle_in_data: If data supplied contains the source handle sending the data, such as when we read data
    from a device using a UUID, we need to know to print the handle separate from the handle
    :param prefix: Prefix all printed lines with the supplied string
    :type data: list of strings or string
    :type is_handle_in_data: bool
    :type prefix: str

    """
    print(prefix + "Data (Copy/Paste version)")
    print(prefix + "==========================")
    if data == -1:
        print(prefix + "Invalid Handle/UUID")
        print(prefix + "=====")
        return
    if data == -2:
        print(prefix + "Permission error. Cannot read supplied handle/UUID.")
        print(prefix + "=====")
        return

    if data is None:
        print(prefix + "No data found from a previous from a previous read operation.")
        print(prefix + "=====")
        return
    if isinstance(data, list):
        for i in data:
            '''chunks = [i[x:x+groupLen] for x in range(0, len(i), groupLen)]
            for chunk in chunks:
                print chunk
            print "-"*(groupLen+1)
            for chunk in chunks:
                print " ".join("{:02x}".format(ord(c)) for c in chunk)'''
            if is_handle_in_data:
                #UUID read response packets contain
                #the originating header in the first two bytes
                #handle reverse order when received
                handle = i[:2][::-1]
                i = i[2:]
                if handle is not None:
                    print(prefix + "Handle:", "".join("{:02x}".format(ord(c)) for c in handle))
                else:
                    print(prefix + "Handle:")
            print(prefix + str(i))
            print(prefix + "-" * len(str(i)))
            print(prefix + " ". join("{:02x}".format(ord(c)) for c in str(i)))
    else:
        if is_handle_in_data:
            # UUID read response packets contain
            # the originating header in the first two bytes
            # handle reverse order when received
            handle = data[:2][::-1]
            i = data[2:]
            if handle is not None:
                print(prefix + "Handle:", "".join("{:02x}".format(ord(c)) for c in handle))
            else:
                print(prefix + "Handle:")
        print(prefix + str(data))
        print(prefix + "-" * len(str(data)))
        print(prefix + " ".join("{:02x}".format(ord(c)) for c in str(data)))
    print(prefix + "=====")
