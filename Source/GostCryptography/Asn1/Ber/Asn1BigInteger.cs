using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1BigInteger : Asn1Type
	{
		private const int MaxBigIntLen = 0x186a0;

		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, BigIntegerTypeCode);
		public static readonly BigInteger Zero = new BigInteger();

		private BigInteger _value;

		public Asn1BigInteger()
		{
			_value = new BigInteger();
		}

		public Asn1BigInteger(BigInteger value)
		{
			_value = value;
		}

		public Asn1BigInteger(string value)
		{
			_value = new BigInteger(value);
		}

		public Asn1BigInteger(string value, int radix)
		{
			_value = new BigInteger(value, radix);
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var length = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			_value = DecodeValue(buffer, length);
			buffer.TypeCode = 2;
		}

		public BigInteger DecodeValue(Asn1DecodeBuffer buffer, int length)
		{
			var ivalue = new byte[length];

			if (length > MaxBigIntLen)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1TooBigIntegerValue, length);
			}

			for (var i = 0; i < length; ++i)
			{
				ivalue[i] = (byte)buffer.ReadByte();
			}

			var integer = new BigInteger();

			if (length > 0)
			{
				integer.SetData(ivalue);
			}

			return integer;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = EncodeValue(buffer, _value, true);

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

			var buffer = new Asn1BerEncodeBuffer();
			var len = EncodeValue(buffer, _value, true);

			outs.EncodeLength(len);
			outs.Write(buffer.MsgCopy);
		}

		private static int EncodeValue(Asn1EncodeBuffer buffer, BigInteger ivalue, bool doCopy)
		{
			var data = ivalue.GetData();
			var length = data.Length;

			for (var i = length - 1; i >= 0; --i)
			{
				if (doCopy)
				{
					buffer.Copy(data[i]);
				}
			}

			return length;
		}

		public virtual bool Equals(long value)
		{
			return _value.Equals(value);
		}

		public override bool Equals(object value)
		{
			var integer = value as Asn1BigInteger;

			if (integer == null)
			{
				return false;
			}

			return _value.Equals(integer._value);
		}

		public override int GetHashCode()
		{
			return _value.GetHashCode();
		}

		public override string ToString()
		{
			return _value.ToString(10);
		}
	}
}