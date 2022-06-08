def message_filter(category, message):
    return lambda x: x.WhichOneof('msg') == category and x.discovery.WhichOneof('msg')==message