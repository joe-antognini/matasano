#! /usr/bin/env python

#
# Matasano crypto challanges
# Set 1
#

import binascii

def hex2base64(a):
  '''Convert a string in hex to a string in base64.'''
  data = binascii.unhexlify(a)
  return binascii.b2a_base64(data).strip()

def fixedXOR(a, b):
  '''Take the XOR of two equal length arrays of bytes.'''

  # Make sure the data are the same length.
  if len(a) != len(b):
    raise ValueError('fixedXOR(): data arrays must be the same length!')
  if type(a) is not str or type(b) is not str:
    raise TypeError('fixedXOR(): input must be a string!')

  a_raw = binascii.unhexlify(a)
  b_raw = binascii.unhexlify(b)

  c = ''.join(map(chr, [ord(i) ^ ord(j) for i, j in zip(a_raw, b_raw)]))
  return c.encode('hex')

if __name__ == '__main__':
  # Challenge 1
  STRING1_1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  RESULT1_1 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  assert hex2base64(STRING1_1) == RESULT1_1

  # Challenge 2
  STRING1_2A = '1c0111001f010100061a024b53535009181c'
  STRING1_2B = '686974207468652062756c6c277320657965'
  RESULT1_2  = '746865206b696420646f6e277420706c6179'
  assert fixedXOR(STRING1_2A, STRING1_2B) == RESULT1_2
