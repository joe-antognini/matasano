#! /usr/bin/env python

#
# Matasano crypto challanges
# Set 1
#

from math import log
from scipy.stats import binom
import numpy
import binascii
import string

en_freq_table = {
  'a' : .08167,
  'b' : .01492,
  'c' : .02782,
  'd' : .04253,
  'e' : .12702,
  'f' : .02228,
  'g' : .02015,
  'h' : .06094,
  'i' : .06966,
  'j' : .00153,
  'k' : .00772,
  'l' : .04025,
  'm' : .02406,
  'n' : .06749,
  'o' : .07507,
  'p' : .01929,
  'q' : .00095,
  'r' : .05987,
  's' : .06327,
  't' : .09056,
  'u' : .02758,
  'v' : .00978,
  'w' : .02360,
  'x' : .00150,
  'y' : .01974,
  'z' : .00074}

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

def score_string(s):
  '''Score a string based on its letter frequency compared to the average
  English letter frequencies.  This is done by returning a log likelihood for
  the given frequency distribution in the input string.

  Parameters:
    s: str

  Returns:
    score: float
  '''

  # Typechecking
  if type(s) is not str:
    raise TypeError('score_string(): input must be string!')

  s_letter_count = {}
  for letter in string.ascii_lowercase:
    s_letter_count[letter] = 0

  # Get the frequency distribution
  for char in s:
    if char in string.ascii_lowercase:
      s_letter_count[char] += 1
    elif char in string.ascii_uppercase:
      s_letter_count[char.lower()] += 1

  total_letters = sum(s_letter_count.values())

  score = 0
  for char in s_letter_count:
    score += log(binom.pmf(s_letter_count[char], total_letters, 
               en_freq_table[char]))

  return score

def single_byte_xor(instring):
  '''Crack a cypher that has been xor'd against a single character.'''
  maxscore = -numpy.inf
  for char in string.ascii_lowercase:
    s = fixedXOR(instring, len(instring) * char)
    score = score_string(s)
    if score > maxscore:
      maxscore = score
      maxchar = char
  return fixedXOR(instring, len(instring) * maxchar)

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

  # Challenge 3
  STRING1_3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
  print single_byte_xor(STRING1_3)
