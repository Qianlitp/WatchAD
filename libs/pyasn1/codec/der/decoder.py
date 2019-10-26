# DER decoder
from libs.pyasn1.codec.cer import decoder

tagMap = decoder.tagMap
typeMap = decoder.typeMap
Decoder = decoder.Decoder

decode = Decoder(tagMap, typeMap)
