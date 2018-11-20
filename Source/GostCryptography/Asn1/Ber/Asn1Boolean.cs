using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Boolean : Asn1Type
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, BooleanTypeCode);
		public static readonly Asn1Boolean FalseValue = new Asn1Boolean(false);
		public static readonly Asn1Boolean TrueValue = new Asn1Boolean(true);

		[NonSerialized]
		public bool Value;

		public Asn1Boolean()
		{
			Value = false;
		}

		public Asn1Boolean(bool value)
		{
			Value = value;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			if (explicitTagging)
			{
				MatchTag(buffer, Tag);
			}

			var num = buffer.Read();

			if (num < 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
			}

			buffer.TypeCode = BooleanTypeCode;
			Value = num != 0;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 1;

			buffer.Copy(Value ? byte.MaxValue : ((byte)0));

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

			outs.EncodeLength(1);
			outs.WriteByte(Value ? -1 : 0);
		}

		public virtual bool Equals(bool value)
		{
			return (Value == value);
		}

		public override bool Equals(object value)
		{
			var flag = value as Asn1Boolean;

			if (flag == null)
			{
				return false;
			}

			return (Value == flag.Value);
		}

		public override int GetHashCode()
		{
			return Value.GetHashCode();
		}

		public override string ToString()
		{
			if (!Value)
			{
				return "FALSE";
			}

			return "TRUE";
		}
	}
}