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
  'z' : .00074,
  '.' : .01306,
  ',' : .01232,
  ';' : .00064,
  ':' : .00068,
  '!' : .00066,
  '?' : .00112,
  '\'': .00486,
  '"' : .00534,
  '-' : .00306,
  ' ' : .16667}

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
    lenscore: float
      The primary score based on how many characters in the alphabet the
      string returns.
    freqscore: float
      The secondary score based on letter frequencies.
  '''

  # Typechecking
  if type(s) is not str:
    raise TypeError('score_string(): input must be string!')

  s_letter_count = {}
  for letter in en_freq_table:
    s_letter_count[letter] = 0

  # Get the frequency distribution
  for char in s:
    if char in string.ascii_uppercase:
      s_letter_count[char.lower()] += 1
    elif char in en_freq_table:
      s_letter_count[char] += 1
    elif ord(char) > 126:
      return (0, -numpy.inf)

  total_letters = sum(s_letter_count.values())
  if total_letters == 0:
    return (0, -numpy.inf)

  score = 0
  for char in s_letter_count:
    score += log(binom.pmf(s_letter_count[char], total_letters, 
               en_freq_table[char]))

  return (total_letters, score)

def single_byte_xor(instring):
  '''Crack a cypher that has been xor'd against a single character.'''
  maxscore = (0, -numpy.inf)
  maxstring = ''
  for char in [chr(x).encode('hex') for x in range(128)]:
    s = fixedXOR(instring, (len(instring) / len(char)) * char).decode('hex')
    lenscore, freqscore = score_string(s)
    if lenscore > maxscore[0]:
      maxscore = (lenscore, freqscore)
      maxstring = s
    elif lenscore == maxscore[0] and freqscore > maxscore[1]:
      maxscore = (lenscore, freqscore)
      maxstring = s
  return (maxstring, maxscore)

def detect_singchar_xor(file):
  '''Find the single line of a file that has been encrypted using a
  single-character XOR.'''
  with open(file) as infile:
    maxscore = (0, -numpy.inf)
    for line in infile:
      s, score = single_byte_xor(line.strip())
      if score[0] > maxscore[0]:
        maxstring = s
        maxscore = score
      elif score[0] == maxscore[0] and score[1] > maxscore[1]:
        maxstring = s
        maxscore = score
    return maxstring

def repeating_key_xor(instring, key):
  '''Encrypt a string with a key using XOR.'''

  outstring = ''
  for i, char in enumerate(instring):
    outstring += fixedXOR(char.encode('hex'), key[i%len(key)].encode('hex'))
  return outstring

def hamming_distance(str1, str2):
  '''Compute the Hamming distance between str1 and str2 (represented as
  bytes).'''

  distance = 0
  for a, b in zip(str1, str2):
    for x, y in zip('{0:08b}'.format(ord(a)), '{0:08b}'.format(ord(b))):
      if x != y:
        distance += 1

  return distance

if __name__ == '__main__':
  # Challenge 1
  STRING1_1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  RESULT1_1 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  assert hex2base64(STRING1_1) == RESULT1_1
  print "Challenge 1 test passed"

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
  print single_byte_xor(STRING1_3)[0]
  print

  # Challenge 4
  print "Challenge 4 solution:"
  print detect_singchar_xor('set1-4.txt'),
  print

  # Challenge 5
  STRING1_5A = 'Burning \'em, if you ain\'t quick and nimble\n'
  STRING1_5B = 'I go crazy when I hear a cymbal'
  STRING1_5 = STRING1_5A + STRING1_5B
  STRING1_5KEY = 'ICE'
  RESULT1_5A = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
  RESULT1_5B = 'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
  RESULT1_5 = RESULT1_5A + RESULT1_5B
  assert repeating_key_xor(STRING1_5, STRING1_5KEY) == RESULT1_5
  print "Challenge 5 test passed"
