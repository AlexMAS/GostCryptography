using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class BigInteger
	{
		private const int AddressBits = 3;
		private const int BitIndexMask = 7;
		private const int BitsPerUnit = 8;
		internal const int MaxBigIntLen = 100000;
		private const int UnitMask = -1;

		[NonSerialized]
		private static readonly int[] BitsPerDigit =
		{
			0, 0, 0x400, 0x658, 0x800, 0x94a, 0xa58, 0xb3b, 0xc00, 0xcaf, 0xd4a, 0xdd7, 0xe58, 0xece, 0xf3b, 0xfa1,
			0x1000, 0x105a, 0x10af, 0x10fe, 0x114a, 0x1192, 0x11d7, 0x1219, 0x1258, 0x1294, 0x12ce, 0x1306, 0x133b, 0x136f, 0x13a1, 0x13d2,
			0x1400, 0x142e, 0x145a, 0x1485, 0x14af
		};

		[NonSerialized]
		private static readonly int[] ByteRadix =
		{
			0, 0, 0x80, 0, 0, 0, 0, 0, 0x40, 0, 100, 0, 0, 0, 0, 0, 0x10
		};

		[NonSerialized]
		private static readonly int[] DigitsPerByte =
		{
			0, 0, 7, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 1
		};

		private static readonly byte[] Zero = new byte[0];

		[NonSerialized]
		private int _sign;

		[NonSerialized]
		private byte[] _value;

		public BigInteger()
		{
			_value = Zero;
			_sign = 0;
		}

		public BigInteger(long value)
			: this(value.ToString())
		{
		}

		public BigInteger(string value)
		{
			Init(value, 10);
		}

		public BigInteger(byte[] value, int sign)
		{
			_value = value;
			_sign = sign;
		}

		public BigInteger(string value, int radix)
		{
			Init(value, radix);
		}

		private static int BitsLeftOf(int x)
		{
			if (x != 0)
			{
				return (UnitMask << (BitsPerUnit - x));
			}

			return UnitMask;
		}

		private static void DestructiveMulAdd(byte[] x, int y, byte z)
		{
			var num = (byte)(y & 0xff);
			var num2 = z;
			var length = x.Length;
			var num5 = 0;

			for (var i = length - 1; i >= 0; i--)
			{
				var num4 = (num * x[i]) + num5;
				x[i] = (byte)num4;
				num5 = num4 >> BitsPerUnit;
			}

			var num7 = x[length - 1] + num2;
			x[length - 1] = (byte)num7;
			num5 = num7 >> BitsPerUnit;

			for (var j = length - 2; j >= 0; j--)
			{
				num7 = x[j] + num5;
				x[j] = (byte)num7;
				num5 = num7 >> BitsPerUnit;
			}
		}

		private static void DivideByInt(ref BigInteger divident, int divisor, ref BigInteger quotient, ref int reminder)
		{
			var index = 0;
			var num3 = 4;
			var num4 = 0;
			var num5 = 0;

			if (divisor == 0)
			{
				return;
			}

			reminder = 0;

			if (divident._sign == 0)
			{
				quotient._sign = 0;
				quotient._value = Zero;
				return;
			}

			quotient._value = new byte[divident._value.Length];

			var num2 = quotient._value.Length - 1;
			quotient._sign = ((quotient._sign * divisor) > 0) ? 1 : -1;

			var num6 = divident._value.Length * 2;

			while (num4 < num6)
			{
				num5 = num5 << 4;
				num4++;
				num5 |= (divident._value[index] >> num3) & 15;

				if (num3 == 0)
				{
					num3 = 4;
					index++;
				}
				else
				{
					num3 = 0;
				}

				ShiftLeft(quotient, 4);

				if (num5 >= divisor)
				{
					quotient._value[num2] = (byte)(quotient._value[num2] | ((byte)((num5 / divisor) & 15)));
					num5 = num5 % divisor;
				}

				reminder = num5;
			}

			quotient._value = RemoveLeadingZeroBytes(quotient._value);
		}

		public bool Equals(long value)
		{
			return Equals(new BigInteger(value));
		}

		public override bool Equals(object value)
		{
			var integer = value as BigInteger;

			if (integer == null)
			{
				return false;
			}

			if (_value.Length != integer._value.Length)
			{
				return false;
			}

			for (var i = 0; i < _value.Length; i++)
			{
				if (_value[i] != integer._value[i])
				{
					return false;
				}
			}

			return true;
		}

		private static void FastCopy(ref BigInteger src, ref BigInteger dst)
		{
			dst._value = new byte[src._value.Length];
			Array.Copy(src._value, 0, dst._value, 0, src._value.Length);
			dst._sign = src._sign;
		}

		private BigInteger GetCopy()
		{
			var integer = new BigInteger();

			if (_value.Length > 0)
			{
				integer._value = new byte[_value.Length];
				Array.Copy(_value, 0, integer._value, 0, _value.Length);
			}
			else
			{
				integer._value = Zero;
			}

			integer._sign = _sign;

			return integer;
		}

		private BigInteger GetCopyAndInverse()
		{
			var integer = new BigInteger();

			if (_value.Length > 0)
			{
				integer._value = new byte[_value.Length];

				if (_sign < 0)
				{
					integer._value = GetData();
					integer._sign = 1;
					return integer;
				}

				Array.Copy(_value, 0, integer._value, 0, _value.Length);
				integer._sign = _sign;

				return integer;
			}

			integer._value = Zero;

			return integer;
		}

		public byte[] GetData()
		{
			int num2;
			var dataLen = GetDataLen();
			var index = _value.Length - 1;
			var num4 = dataLen - 1;

			if (_sign == 0)
			{
				return Zero;
			}

			var buffer = new byte[dataLen];

			if (_sign >= 0)
			{
				num2 = _value.Length - 1;

				while (((num2 >= 0) && (num4 >= 0)) && (index >= 0))
				{
					buffer[num4] = _value[index];
					num2--;
					num4--;
					index--;
				}

				if ((dataLen - _value.Length) > 0)
				{
					buffer[num4] = 0;
				}

				return buffer;
			}

			num2 = _value.Length - 1;

			while (((num2 >= 0) && (num4 >= 0)) && (index >= 0))
			{
				unchecked
				{
					buffer[num4] = (byte)-_value[index];
				}

				if (_value[index] != 0)
				{
					num2--;
					num4--;
					index--;
					break;
				}

				num2--;
				num4--;
				index--;
			}

			while (((num2 >= 0) && (num4 >= 0)) && (index >= 0))
			{
				unchecked
				{
					buffer[num4] = (byte)~_value[index];
				}

				num2--;
				num4--;
				index--;
			}

			if ((dataLen - _value.Length) > 0)
			{
				buffer[num4] = 0xff;
			}

			return buffer;
		}

		private int GetDataLen()
		{
			if (_sign == 0)
			{
				return 1;
			}

			if ((_sign > 0) && ((_value[0] & 0x80) != 0))
			{
				return (_value.Length + 1);
			}

			if (_sign < 0)
			{
				var num = _value[0];

				if ((_value.Length == 1) || ((_value.Length > 1) && (_value[1] == 0)))
				{
					num = (byte)~(num - 1);
				}
				else
				{
					unchecked
					{
						num = (byte)~num;
					}
				}

				if ((num & 0x80) == 0)
				{
					return (_value.Length + 1);
				}
			}

			return _value.Length;
		}

		public override int GetHashCode()
		{
			if (_value == null)
			{
				return base.GetHashCode();
			}

			if (_value.Length == 0)
			{
				return base.GetHashCode();
			}

			var num = 0;
			var num2 = (_value.Length > 20) ? 20 : _value.Length;

			for (var i = 0; i < num2; i++)
			{
				num ^= _value[i];
			}

			return num;
		}

		public void Init(string val, int radix)
		{
			var str = "";

			if (val[0] == '-')
			{
				val = val.Substring(1);
				str = "-";
			}

			if (val.StartsWith("0x"))
			{
				radix = 0x10;
				val = val.Substring(2);
			}
			else if (val.StartsWith("0b"))
			{
				radix = 2;
				val = val.Substring(2);
			}
			else if (val.StartsWith("0o"))
			{
				radix = 8;
				val = val.Substring(2);
			}

			val = str + val;
			var startIndex = 0;
			var length = val.Length;

			if (((radix != 2) && (radix != 0x10)) && ((radix != 10) && (radix != 8)))
			{
				throw new FormatException(Resources.Asn1InvalidFormatForBigIntegerValue);
			}

			if (val.Length == 0)
			{
				throw new FormatException(Resources.Asn1ZeroLengthBigInteger);
			}

			_sign = 1;

			var index = val.IndexOf('-');

			if (index != -1)
			{
				if (index != 0)
				{
					throw new FormatException(Resources.Asn1IllegalEmbeddedMinusSign);
				}

				if (val.Length == 1)
				{
					throw new FormatException(Resources.Asn1ZeroLengthBigInteger);
				}

				_sign = -1;

				startIndex = 1;
			}

			while ((startIndex < length) && (val[startIndex] == '0'))
			{
				startIndex++;
			}

			if (startIndex == length)
			{
				_sign = 0;
				_value = Zero;
			}
			else
			{
				var num2 = length - startIndex;
				var num5 = Asn1Util.UrShift(num2 * BitsPerDigit[radix], 10) + 1;
				var num1 = (num5 + 0x1f) / 0x20;

				_value = new byte[num2];

				var num6 = num2 % DigitsPerByte[radix];

				if (num6 == 0)
				{
					num6 = DigitsPerByte[radix];
				}

				var str2 = val.Substring(startIndex, num6);
				startIndex += num6;

				_value[_value.Length - 1] = Convert.ToByte(str2, radix);

				if (_value[_value.Length - 1] < 0)
				{
					throw new FormatException(Resources.Asn1IllegalDigit);
				}

				var y = ByteRadix[radix];
				byte z;

				while (startIndex < val.Length)
				{
					str2 = val.Substring(startIndex, DigitsPerByte[radix]);
					startIndex += DigitsPerByte[radix];
					z = Convert.ToByte(str2, radix);

					if (z < 0)
					{
						throw new FormatException(Resources.Asn1IllegalDigit);
					}

					DestructiveMulAdd(_value, y, z);
				}

				_value = TrustedStripLeadingZeroInts(_value);
			}
		}

		private static string IntToStr(long value, int radix)
		{
			var chArray = new char[0x22];
			var num = 0;
			var str = "";

			if ((radix >= 2) && (radix <= 0x10))
			{
				while (num < 0x22)
				{
					chArray[num++] = (char)((ushort)(value % radix));

					if ((value /= radix) == 0L)
					{
						break;
					}
				}

				while (num != 0)
				{
					var ch = chArray[--num];

					if (ch < '\n')
					{
						str = str + ((char)(ch + '0'));
					}
					else
					{
						str = str + ((char)((ch - '\n') + 0x41));
					}
				}
			}

			return str;
		}

		public bool IsNegative()
		{
			return (_sign < 0);
		}

		private char NibbleToHexChar(int b)
		{
			if ((b >= 0) && (b <= 9))
			{
				return (char)(b + 0x30);
			}

			if ((b >= 10) && (b <= 15))
			{
				return (char)((b - 10) + 0x61);
			}

			return '?';
		}

		public static implicit operator BigInteger(long value)
		{
			return new BigInteger(value);
		}

		private static byte[] RemoveLeadingZeroBytes(byte[] data)
		{
			if (data.Length == 0)
			{
				return data;
			}

			var index = 0;

			while ((index < data.Length) && (data[index] == 0))
			{
				index++;
			}

			var destinationArray = new byte[data.Length - index];
			Array.Copy(data, index, destinationArray, 0, data.Length - index);

			return destinationArray;
		}

		public void SetData(byte[] ivalue)
		{
			if (ivalue.Length > MaxBigIntLen)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1TooBigIntegerValue, ivalue.Length);
			}

			if ((ivalue.Length > 0) && ((ivalue[0] & 0x80) != 0))
			{
				var index = 0;
				var num = 0;

				_sign = -1;

				while ((num < ivalue.Length) && (ivalue[index] == 0xff))
				{
					num++;
					index++;
				}

				var num2 = num;

				while ((num2 < ivalue.Length) && (ivalue[index] == 0))
				{
					num2++;
					index++;
				}

				var num3 = (num2 == ivalue.Length) ? 1 : 0;
				_value = new byte[(ivalue.Length - num) + num3];
				index = num;

				var num4 = num;

				while (num < ivalue.Length)
				{
					unchecked
					{
						_value[(num - num4) + num3] = (byte)~ivalue[index];
					}

					num++;
					index++;
				}

				for (num = _value.Length - 1; (_value[num] = (byte)(_value[num] + 1)) == 0; num--)
				{
				}

				_value = RemoveLeadingZeroBytes(_value);
			}
			else
			{
				_value = RemoveLeadingZeroBytes(ivalue);
				_sign = (ivalue.Length == 0) ? 0 : 1;
			}
		}

		private static int ShiftLeft(BigInteger data, uint shift)
		{
			var value = data._value;
			var length = value.Length;
			var index = (int)(shift >> AddressBits);
			var num3 = ((int)shift) & BitIndexMask;
			var num4 = 8 - num3;
			var num5 = 0;
			var num7 = length;

			if (length != 0)
			{
				length = length << AddressBits;
				var num6 = (int)((((length - shift) + 8L) - 1L) >> AddressBits);

				while (num5 < (num6 - 1))
				{
					value[num5++] = (byte)((value[index] << num3) | ((num4 == 8) ? 0 : (value[index + 1] >> num4)));
					index++;
				}

				length &= BitIndexMask;
				value[num5] = (num7 == num6) ? ((byte)((value[index] & BitsLeftOf(length)) << num3)) : ((byte)((value[index] << num3) | ((num4 == 8) ? 0 : ((value[index + 1] & BitsLeftOf(length)) >> num4))));

				if (num6 < num7)
				{
					for (var i = num6; i < (num7 - num6); i++)
					{
						value[i] = 0;
					}
				}
			}

			return 0;
		}

		public override string ToString()
		{
			return ToString(10);
		}

		public string ToString(int radix)
		{
			if ((radix == 2) || (radix == 0x10))
			{
				int num;
				int num2;

				if (radix == 2)
				{
					num2 = 8;
					num = 1;
				}
				else
				{
					num2 = 2;
					num = 4;
				}

				var num3 = num2 * GetDataLen();
				var chArray = new char[num3];
				var index = num3 - 1;

				for (var i = _value.Length - 1; i >= 0; i--)
				{
					byte num6;
					int num8;

					if (_sign < 0)
					{
						unchecked
						{
							num6 = (byte)~_value[i];
						}

						if ((_sign < 0) && ((num6 = (byte)(num6 + 1)) != 0))
						{
							_sign = 0;
						}
					}
					else
					{
						num6 = _value[i];
					}

					var num7 = num8 = 0;

					while (num7 < num2)
					{
						var b = (num6 >> num8) & ((1 << num) - 1);
						chArray[index] = NibbleToHexChar(b);
						num7++;
						index--;
						num8 += num;
					}
				}

				while (index >= 0)
				{
					chArray[index--] = '0';
				}

				return new string(chArray);
			}

			var reminder = 0;
			var str = "";
			var quotient = new BigInteger();

			var copy = (radix == 10) ? GetCopy() : GetCopyAndInverse();

			do
			{
				DivideByInt(ref copy, ByteRadix[radix], ref quotient, ref reminder);
				var str2 = IntToStr(reminder, radix);
				var length = str2.Length;

				str = str2 + str;

				if ((quotient._value.Length != 0) || (radix != 10))
				{
					int num12;

					for (num12 = length; num12 < DigitsPerByte[radix]; num12++)
					{
						str = '0' + str;
					}

					FastCopy(ref quotient, ref copy);

					if (((quotient._value.Length == 0) && (_sign > 0)) && ((radix != 10) && ((reminder & 0x80) != 0)))
					{
						str = '0' + str;
					}
				}
				else if ((_sign < 0) && (radix == 10))
				{
					str = '-' + str;
				}

			}
			while ((quotient._value != null) && (quotient._value.Length != 0));

			return str;
		}

		private static byte[] TrustedStripLeadingZeroInts(byte[] val)
		{
			var index = 0;

			while ((index < val.Length) && (val[index] == 0))
			{
				index++;
			}

			if (index <= 0)
			{
				return val;
			}

			var buffer = new byte[val.Length - index];

			for (var i = 0; i < (val.Length - index); i++)
			{
				buffer[i] = val[index + i];
			}

			return buffer;
		}
	}
}