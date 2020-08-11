#ifndef DBXTOOL_X509_H
#define DBXTOOL_X509_H

#define SMALLEST_POSSIBLE_DER_SEQ 3

static inline int32_t
__attribute__((unused))
GetASN1SequenceSize(uint8_t *Location, uint32_t Size)
{
  uint8_t I;
  uint8_t Octets;
  uint32_t DERLength = 0;

  if (Size < SMALLEST_POSSIBLE_DER_SEQ)
    return -1;

  // If it's not a CONSTRUCTED SEQUENCE it's not a certificate
  if (Location[0] != 0x30)
    return -1;

  if (!(Location[1] & 0x80)) {
    // Short form, which is too small to hold a certificate.
    return -1;
  }

  // Long form
  Octets = Location[1] & 0x7;

  // There is no chance our data is more than 3GB.
  if (Octets > 4 || (Octets == 4 && (Location[2] & 0x8)))
    return -1;

  // and if our size won't fit in the data it's wrong as well
  if (Size - 2 < Octets)
    return -1;

  for (I = 0; I < Octets; I++) {
    DERLength <<= 8;
    DERLength |= Location[I + 2];
  }
  // and if DERLength is greater than what's left, it's bad too.
  if (Size - 2 - Octets < DERLength)
    return -1;

  // or else it's a reasonable certificate from a size point of view.
  return DERLength + 4;
}

#undef SMALLEST_POSSIBLE_DER_SEQ

#endif
