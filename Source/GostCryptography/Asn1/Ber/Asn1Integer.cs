using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Integer : Asn1Type
	{
		public const int SizeOfInt = 4;
		public const int SizeOfLong = 8;
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, BigIntegerTypeCode);

		[NonSerialized]
		public long Value;

		public Asn1Integer()
		{
			Value = 0L;
		}

		public Asn1Integer(long value)
		{
			Value = value;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var length = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			Value = Asn1RunTime.DecodeIntValue(buffer, length, true);
			buffer.TypeCode = BigIntegerTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = buffer.EncodeIntValue(Value);

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

			outs.EncodeIntValue(Value, true);
		}

		public virtual bool Equals(long value)
		{
			return (Value == value);
		}

		public override bool Equals(object value)
		{
			var integer = value as Asn1Integer;

			if (integer == null)
			{
				return false;
			}

			return (Value == integer.Value);
		}

		public virtual int GetBitCount()
		{
			return Asn1RunTime.GetLongBitCount(Value);
		}

		public static int GetBitCount(long ivalue)
		{
			return Asn1RunTime.GetLongBitCount(ivalue);
		}

		public override int GetHashCode()
		{
			return Value.GetHashCode();
		}

		public override string ToString()
		{
			return Convert.ToString(Value);
		}
	}
}