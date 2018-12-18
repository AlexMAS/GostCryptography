using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Real : Asn1Type
	{
		private const int MinusInfinity = 0x41;
		private const int PlusInfinity = 0x40;
		private const int RealBase2 = 0;
		private const int RealBase8 = 0x10;
		private const int RealBase16 = 0x20;
		private const int RealBaseMask = 0x30;
		private const int RealBinary = 0x80;
		private const int RealExplen1 = 0;
		private const int RealExplen2 = 1;
		private const int RealExplen3 = 2;
		private const int RealExplenLong = 3;
		private const int RealExplenMask = 3;
		private const int RealFactorMask = 12;
		private const int RealIso6093Mask = 0x3f;

		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, RealTypeCode);

		[NonSerialized]
		public double Value;

		public Asn1Real()
		{
			Value = 0.0;
		}

		public Asn1Real(double value)
		{
			Value = value;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var length = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;

			if (length == 0)
			{
				Value = 0.0;
			}
			else
			{
				var num2 = buffer.ReadByte();

				if (length == 1)
				{
					switch (num2)
					{
						case PlusInfinity:
							Value = double.PositiveInfinity;
							return;

						case MinusInfinity:
							Value = double.NegativeInfinity;
							return;
					}

					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
				}

				length--;

				if ((num2 & RealBinary) == 0)
				{
					var num8 = length;
					var num9 = 0;

					var builder = new StringBuilder { Length = num8 };

					while (num8 > 0)
					{
						var num7 = buffer.Read();

						if (num7 == -1)
						{
							throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
						}

						builder[num9++] = (char)num7;
						num8--;
					}

					var num10 = num2 & RealIso6093Mask;
					var num11 = 0;

					for (var i = 0; i < builder.Length; i++)
					{
						var ch = builder[i];

						if ((num10 >= 2) && (ch == ','))
						{
							builder[i] = '.';
							num11++;
						}
						else if (((num10 >= 1) && (((ch >= '0') && (ch <= '9')) || ((ch == '+') || (ch == '-')))) || (((num10 >= 2) && (ch == '.')) || ((num10 == 3) && ((ch == 'E') || (ch == 'e')))))
						{
							num11++;
						}
						else if ((num11 != 0) || (ch != ' '))
						{
							throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
						}
					}
					try
					{
						Value = double.Parse(builder.ToString());
					}
					catch (FormatException)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}
				}
				else
				{
					int num6;
					int num3;

					switch ((num2 & RealExplenMask))
					{
						case RealExplen1:
							num3 = 1;
							break;

						case RealExplen2:
							num3 = 2;
							break;

						case RealExplen3:
							num3 = 3;
							break;

						default:
							num3 = buffer.ReadByte();
							length--;
							break;
					}

					var num4 = (int)Asn1RunTime.DecodeIntValue(buffer, num3, true);
					length -= num3;

					var num5 = Asn1RunTime.DecodeIntValue(buffer, length, false) * (1L << ((num2 & RealFactorMask) >> 2));

					switch ((num2 & RealBaseMask))
					{
						case RealBase2:
							num6 = 2;
							break;

						case RealBase8:
							num6 = 8;
							break;

						case RealBase16:
							num6 = 16;
							break;

						default:
							throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					Value = num5 * Math.Pow(num6, num4);

					if ((num2 & PlusInfinity) != 0)
					{
						Value = -Value;
					}
				}

				buffer.TypeCode = RealTypeCode;
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (double.IsNegativeInfinity(Value))
			{
				len = buffer.EncodeIntValue(MinusInfinity);
			}
			else if (double.IsPositiveInfinity(Value))
			{
				len = buffer.EncodeIntValue(PlusInfinity);
			}

			else if (Value != 0.0)
			{
				var num2 = BitConverter.DoubleToInt64Bits(Value);
				var num3 = ((num2 >> RealIso6093Mask) == 0L) ? 1 : -1;
				var num4 = ((int)((num2 >> 0x34) & 0x7ffL)) - 0x433;
				var w = (num4 == 0) ? ((num2 & 0xfffffffffffffL) << 1) : ((num2 & 0xfffffffffffffL) | 0x10000000000000L);

				if (w != 0L)
				{
					var bits = TrailingZerosCnt(w);
					w = Asn1Util.UrShift(w, bits);
					num4 += bits;
				}

				len += buffer.EncodeIntValue(w);

				var num7 = buffer.EncodeIntValue(num4);
				len += num7;

				var num8 = RealBinary;

				if (num3 == -1)
				{
					num8 |= PlusInfinity;
				}

				switch (num7)
				{
					case RealExplen2:
						break;

					case RealExplen3:
						num8 |= 1;
						break;

					case RealExplenLong:
						num8 |= 2;
						break;

					default:
						num8 |= 3;
						len += buffer.EncodeIntValue(num7);
						break;
				}

				buffer.Copy((byte)num8);
				len++;
			}

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			if (Value == 0.0)
			{
				outs.EncodeLength(0);
			}
			else if (Value == double.NegativeInfinity)
			{
				outs.EncodeIntValue(MinusInfinity, true);
			}
			else if (Value == double.PositiveInfinity)
			{
				outs.EncodeIntValue(PlusInfinity, true);
			}
			else
			{
				var len = 1;
				var num2 = BitConverter.DoubleToInt64Bits(Value);
				var num3 = ((num2 >> RealIso6093Mask) == 0L) ? 1 : -1;
				var num4 = ((int)((num2 >> 0x34) & 0x7ffL)) - 0x433;
				var w = (num4 == 0) ? ((num2 & 0xfffffffffffffL) << 1) : ((num2 & 0xfffffffffffffL) | 0x10000000000000L);

				if (w != 0L)
				{
					var bits = TrailingZerosCnt(w);
					w = Asn1Util.UrShift(w, bits);
					num4 += bits;
					len += Asn1Util.GetUlongBytesCount(w);
				}
				else
				{
					len++;
				}

				var num7 = RealBinary;

				if (num3 == -1)
				{
					num7 |= PlusInfinity;
				}

				var bytesCount = Asn1Util.GetBytesCount(num4);
				len += bytesCount;

				switch (bytesCount)
				{
					case RealExplen2:
						break;

					case RealExplen3:
						num7 |= 1;
						break;

					case RealExplenLong:
						num7 |= 2;
						break;

					default:
						num7 |= 3;
						len++;
						break;
				}

				outs.EncodeLength(len);
				outs.WriteByte((byte)num7);

				if ((num7 & 3) == 3)
				{
					outs.EncodeIntValue(bytesCount, false);
				}

				outs.EncodeIntValue(num4, false);
				outs.EncodeIntValue(w, false);
			}
		}

		public virtual bool Equals(double value)
		{
			return (Value == value);
		}

		public override bool Equals(object value)
		{
			var real = value as Asn1Real;

			if (real == null)
			{
				return false;
			}

			return (Value == real.Value);
		}

		public override int GetHashCode()
		{
			return Value.GetHashCode();
		}

		public override string ToString()
		{
			return Value.ToString();
		}

		private static int TrailingZerosCnt(long w)
		{
			var num = Asn1RunTime.IntTrailingZerosCnt((int)w);

			if (num >= RealBase16)
			{
				return (Asn1RunTime.IntTrailingZerosCnt((int)Asn1Util.UrShift(w, RealBase16)) + RealBase16);
			}

			return num;
		}
	}
}