#! /usr/bin/env python

#
# Matasano Crypto Pals
# Set 1
#

import binascii
import base64
from freqs import *

def hex2base64(a):
  '''Convert a string in hex to a string in base64.'''
  data = binascii.unhexlify(a)
  return base64.b64encode(data)

def fixedXOR(s1, s2):
  '''Return the XOR of two hexadecimal strings, s1 and s2.'''

  int1 = int(s1, base=16)
  int2 = int(s2, base=16)

  return hex(int1 ^ int2)[2:].rstrip('L')

def score_hex(s):
  '''Return a score associated with how likely the string is given English
  character frequencies.'''

  rare_char_score = -4
  nonascii_score = -100

  score = 0
  for idx in xrange(len(s) / 2):
    b = s[2*idx:2*idx+2]
    c = chr(int(b, base=16))
    if c in en_log_freqs:
      score += en_log_freqs[c]
    elif 31 < ord(c) < 127:
      score += rare_char_score
    else:
      score += nonascii_score

  return score

def single_byte_xor(instring):
  '''Decode a string that has been encrypted against a single character.'''

  maxscore = None
  best_string = None
  for i in xrange(128):
    repeated_char = (len(instring)+1) / 2 * hex(i)[2:]
    s = fixedXOR(instring, repeated_char)
    score = score_hex(s)
    if score > maxscore:
      maxscore = score
      best_string = s

  return best_string

def detect_single_char_xor(filename):
  '''Find the line in the file that has been encrypted with single key
  XOR.'''

  maxscore = None
  best_line = None
  with open(filename) as infile:
    lines = infile.readlines()

  for line in lines:
    decoded_line = single_key_xor(line)
    if score_hex(decoded_line) > maxscore:
      best_line = decoded_line

  return best_line

if __name__ == '__main__':
  # Challenge 1
  STRING1_1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  RESULT1_1 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  assert hex2base64(STRING1_1) == RESULT1_1
  print "Challenge 1 test passed"
  print

  # Challenge 2
  STRING1_2A = '1c0111001f010100061a024b53535009181c'
  STRING1_2B = '686974207468652062756c6c277320657965'
  RESULT1_2  = '746865206b696420646f6e277420706c6179'
  assert fixedXOR(STRING1_2A, STRING1_2B) == RESULT1_2
  print "Challenge 2 test passed"
  print

  # Challenge 3
  STRING1_3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
  print "Challenge 3 solution:"
  print single_byte_xor(STRING1_3).decode('hex')
  print

  # Challenge 4
  print "Challenge 4 solution:"
  print detect_singchar_xor('set1-4.txt'),
  print

