def message_filter(category, message):
    return lambda x: x.WhichOneof('msg') == category and getattr(x, category).WhichOneof('msg')==message

def is_message_type(message, category, message_type):
    if message.WhichOneof('msg') == category:
        return (hasattr(message, category) and getattr(message, category).WhichOneof('msg') == message_type)