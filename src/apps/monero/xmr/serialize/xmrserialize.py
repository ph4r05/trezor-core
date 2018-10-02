'''
Minimal streaming codec for a Monero binary serialization.
Used for a binary serialization in blockchain and for hash computation for signatures.

Equivalent of BEGIN_SERIALIZE_OBJECT(), /src/serialization/serialization.h

- The wire binary format does not use tags. Structure has to be read from the binary stream
with the scheme specified in order to parse the structure.

- Heavily uses variable integer serialization - similar to the UTF8 or LZ4 number encoding.

- Supports: blob, string, integer types - variable or fixed size, containers of elements,
            variant types, messages of elements

For de-serializing (loading) types, object with `AsyncReader`
interface is required:

>>> class AsyncReader:
>>>     async def areadinto(self, buffer):
>>>         """
>>>         Reads `len(buffer)` bytes into `buffer`, or raises `EOFError`.
>>>         """

For serializing (dumping) types, object with `AsyncWriter` interface is
required:

>>> class AsyncWriter:
>>>     async def awrite(self, buffer):
>>>         """
>>>         Writes all bytes from `buffer`, or raises `EOFError`.
>>>         """
'''

from apps.monero.xmr.serialize.base_types import IntType, UVarintType, XmrType
from apps.monero.xmr.serialize.erefs import eref, get_elem, set_elem
from apps.monero.xmr.serialize.int_serialize import (
    dump_uint,
    dump_uvarint,
    load_uint,
    load_uvarint,
)
from apps.monero.xmr.serialize.message_types import (
    BlobType,
    ContainerType,
    MessageType,
    UnicodeType,
    VariantType,
    container_elem_type,
)


class Archive:
    """
    Archive object for object binary serialization / deserialization.
    Resembles Archive API from the Monero codebase or Boost serialization archive.

    The design goal is to provide uniform API both for serialization and deserialization
    so the code is not duplicated for serialization and deserialization but the same
    for both ways in order to minimize potential bugs in the code.

    In order to use the archive for both ways we have to use so-called field references
    as we cannot directly modify given element as a parameter (value-passing) as its performed
    in C++ code. see: eref(), get_elem(), set_elem()
    """

    def __init__(self, iobj, writing=True, **kwargs):
        self.writing = writing
        self.iobj = iobj

    def uvarint(self, elem):
        """
        Uvarint
        """
        if self.writing:
            return dump_uvarint(self.iobj, elem)
        else:
            return load_uvarint(self.iobj)

    def uint(self, elem, elem_type=None, width=None):
        """
        Fixed size int
        """
        if self.writing:
            return dump_uint(self.iobj, elem, width if width else elem_type.WIDTH)
        else:
            return load_uint(self.iobj, width if width else elem_type.WIDTH)

    def unicode_type(self, elem):
        """
        Unicode type
        """
        if self.writing:
            return dump_unicode(self.iobj, elem)
        else:
            return load_unicode(self.iobj)

    def blob(self, elem=None, elem_type=None, params=None):
        """
        Loads/dumps blob
        """
        elem_type = elem_type if elem_type else elem.__class__
        if self.writing:
            return dump_blob(self.iobj, elem=elem, elem_type=elem_type, params=params)
        else:
            return load_blob(self.iobj, elem_type=elem_type, params=params, elem=elem)

    def container(self, container=None, container_type=None, params=None):
        """
        Loads/dumps container
        """
        if self.writing:
            return self._dump_container(container, container_type, params)
        else:
            return self._load_container(
                container_type, params=params, container=container
            )

    def container_size(self, container_len=None, container_type=None, params=None):
        """
        Container size
        """
        if self.writing:
            return self._dump_container_size(container_len, container_type, params)
        else:
            raise ValueError("Not supported")

    def variant(self, elem=None, elem_type=None, params=None, wrapped=None):
        """
        Loads/dumps variant type
        """
        elem_type = elem_type if elem_type else elem.__class__
        if self.writing:
            return self._dump_variant(
                elem=elem,
                elem_type=elem_type if elem_type else elem.__class__,
                params=params,
            )
        else:
            return self._load_variant(
                elem_type=elem_type if elem_type else elem.__class__,
                params=params,
                elem=elem,
                wrapped=wrapped,
            )

    def message(self, msg, msg_type=None):
        """
        Loads/dumps message
        """
        msg_type = msg_type if msg_type is not None else msg.__class__
        if self.writing:
            return self._dump_message(msg, msg_type=msg_type)
        else:
            return self._load_message(msg_type, msg=msg)

    def message_field(self, msg, field, fvalue=None):
        """
        Dumps/Loads message field
        """
        if self.writing:
            self._dump_message_field(msg, field, fvalue=fvalue)
        else:
            self._load_message_field(msg, field)

    def _get_type(self, elem_type):
        if issubclass(elem_type, XmrType):
            return elem_type
        else:
            # Can happen due to unimport.
            raise ValueError("XMR serialization hierarchy broken")

    def _is_type(self, elem_type, test_type):
        return issubclass(elem_type, test_type)

    def field(self, elem=None, elem_type=None, params=None):
        elem_type = elem_type if elem_type else elem.__class__
        fvalue = None

        etype = self._get_type(elem_type)
        if self._is_type(etype, UVarintType):
            fvalue = self.uvarint(get_elem(elem))

        elif self._is_type(etype, IntType):
            fvalue = self.uint(get_elem(elem), elem_type)

        elif self._is_type(etype, BlobType):
            fvalue = self.blob(get_elem(elem), elem_type, params)

        elif self._is_type(etype, UnicodeType):
            fvalue = self.unicode_type(get_elem(elem))

        elif self._is_type(etype, VariantType):
            fvalue = self.variant(get_elem(elem), elem_type, params)

        elif self._is_type(etype, ContainerType):
            fvalue = self.container(get_elem(elem), elem_type, params)

        elif self._is_type(etype, MessageType):
            fvalue = self.message(get_elem(elem), elem_type)

        else:
            raise TypeError(
                "unknown type: %s %s %s" % (elem_type, type(elem_type), elem)
            )

        return fvalue if self.writing else set_elem(elem, fvalue)

    def dump_field(self, elem, elem_type, params=None):
        return self.field(elem, elem_type, params)

    def load_field(self, elem_type, params=None, elem=None):
        return self.field(elem, elem_type, params)

    def _dump_container_size(self, container_len, container_type, params=None):
        """
        Dumps container size - per element streaming
        """
        if not container_type or not container_type.FIX_SIZE:
            dump_uvarint(self.iobj, container_len)
        elif container_len != container_type.SIZE:
            raise ValueError(
                "Fixed size container has not defined size: %s" % container_type.SIZE
            )

    def _dump_container(self, container, container_type, params=None):
        """
        Dumps container of elements to the writer.
        """
        self._dump_container_size(len(container), container_type)

        elem_type = container_elem_type(container_type, params)

        for elem in container:
            self.dump_field(elem, elem_type, params[1:] if params else None)

    def _load_container(self, container_type, params=None, container=None):
        """
        Loads container of elements from the reader. Supports the container ref.
        Returns loaded container.
        """

        c_len = (
            container_type.SIZE if container_type.FIX_SIZE else load_uvarint(self.iobj)
        )
        if container and c_len != len(container):
            raise ValueError("Size mismatch")

        elem_type = container_elem_type(container_type, params)
        res = container if container else []
        for i in range(c_len):
            fvalue = self.load_field(
                elem_type,
                params[1:] if params else None,
                eref(res, i) if container else None,
            )
            if not container:
                res.append(fvalue)
        return res

    def _dump_message_field(self, msg, field, fvalue=None):
        """
        Dumps a message field to the writer. Field is defined by the message field specification.
        """
        fname, ftype, params = field[0], field[1], field[2:]
        fvalue = getattr(msg, fname, None) if fvalue is None else fvalue
        self.dump_field(fvalue, ftype, params)

    def _load_message_field(self, msg, field):
        """
        Loads message field from the reader. Field is defined by the message field specification.
        Returns loaded value, supports field reference.
        """
        fname, ftype, params = field[0], field[1], field[2:]
        self.load_field(ftype, params, eref(msg, fname))

    def _dump_message(self, msg, msg_type=None):
        """
        Dumps message to the writer.
        """
        mtype = msg.__class__ if msg_type is None else msg_type
        fields = mtype.f_specs()
        for field in fields:
            self._dump_message_field(msg=msg, field=field)

    def _load_message(self, msg_type, msg=None):
        """
        Loads message if the given type from the reader.
        Supports reading directly to existing message.
        """
        msg = msg_type() if msg is None else msg
        fields = msg_type.f_specs() if msg_type else msg.__class__.f_specs()
        for field in fields:
            self._load_message_field(msg, field)

        return msg

    def _dump_variant(self, elem, elem_type=None, params=None):
        """
        Dumps variant type to the writer.
        Supports both wrapped and raw variant.
        """
        if isinstance(elem, VariantType) or elem_type.WRAPS_VALUE:
            dump_uint(self.iobj, elem.variant_elem_type.VARIANT_CODE, 1)
            self.dump_field(getattr(elem, elem.variant_elem), elem.variant_elem_type)

        else:
            fdef = find_variant_fdef(elem_type, elem)
            dump_uint(self.iobj, fdef[1].VARIANT_CODE, 1)
            self.dump_field(elem, fdef[1])

    def _load_variant(self, elem_type, params=None, elem=None, wrapped=None):
        """
        Loads variant type from the reader.
        Supports both wrapped and raw variant.
        """
        is_wrapped = (
            (isinstance(elem, VariantType) or elem_type.WRAPS_VALUE)
            if wrapped is None
            else wrapped
        )
        if is_wrapped:
            elem = elem_type() if elem is None else elem

        tag = load_uint(self.iobj, 1)
        for field in elem_type.f_specs():
            ftype = field[1]
            if ftype.VARIANT_CODE == tag:
                fvalue = self.load_field(
                    ftype, field[2:], elem if not is_wrapped else None
                )
                if is_wrapped:
                    elem.set_variant(field[0], fvalue)
                return elem if is_wrapped else fvalue
        raise ValueError("Unknown tag: %s" % tag)


def dump_blob(writer, elem, elem_type, params=None):
    """
    Dumps blob message to the writer.
    Supports both blob and raw value.
    """
    elem_is_blob = isinstance(elem, BlobType)
    elem_params = elem if elem_is_blob or elem_type is None else elem_type
    data = bytes(getattr(elem, BlobType.DATA_ATTR) if elem_is_blob else elem)

    if not elem_params.FIX_SIZE:
        dump_uvarint(writer, len(elem))
    elif len(data) != elem_params.SIZE:
        raise ValueError("Fixed size blob has not defined size: %s" % elem_params.SIZE)
    writer.write(data)


def load_blob(reader, elem_type, params=None, elem=None):
    """
    Loads blob from reader to the element. Returns the loaded blob.
    """
    ivalue = elem_type.SIZE if elem_type.FIX_SIZE else load_uvarint(reader)
    fvalue = bytearray(ivalue)
    reader.readinto(fvalue)

    if elem is None:
        return fvalue  # array by default

    elif isinstance(elem, BlobType):
        setattr(elem, elem_type.DATA_ATTR, fvalue)
        return elem

    else:
        elem.extend(fvalue)

    return elem


def dump_unicode(writer, elem):
    dump_uvarint(writer, len(elem))
    writer.write(bytes(elem, "utf8"))


def load_unicode(reader):
    ivalue = load_uvarint(reader)
    fvalue = bytearray(ivalue)
    reader.readinto(fvalue)
    return str(fvalue, "utf8")


def find_variant_fdef(elem_type, elem):
    fields = elem_type.f_specs()
    for x in fields:
        if isinstance(elem, x[1]):
            return x

    # Not direct hierarchy
    name = elem.__class__.__name__
    for x in fields:
        if name == x[1].__name__:
            return x

    raise ValueError("Unrecognized variant: %s" % elem)
