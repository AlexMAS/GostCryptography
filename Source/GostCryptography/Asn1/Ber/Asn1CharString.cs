using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1CharString : Asn1Type
	{
		[NonSerialized]
		protected StringBuilder StringBuffer;

		[NonSerialized]
		private readonly short _typeCode;

		[NonSerialized]
		public string Value;


		protected internal Asn1CharString(short typeCode)
		{
			Value = new StringBuilder().ToString();
			_typeCode = typeCode;
		}

		protected internal Asn1CharString(string data, short typeCode)
		{
			Value = data;
			_typeCode = typeCode;
		}


		public override int Length
		{
			get { return Value.Length; }
		}

		protected virtual void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength, Asn1Tag tag)
		{
			int num2;
			var elemLength = explicitTagging ? MatchTag(buffer, tag) : implicitLength;
			var num3 = elemLength;
			var num4 = 0;

			if (StringBuffer == null)
			{
				StringBuffer = new StringBuilder();
			}

			var lastTag = buffer.LastTag;

			if ((lastTag == null) || !lastTag.Constructed)
			{
				if (num3 < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
				}

				StringBuffer.Length = num3;

				while (num3 > 0)
				{
					num2 = buffer.Read();

					if (num2 == -1)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
					}

					StringBuffer[num4++] = (char)num2;
					num3--;
				}
			}
			else
			{
				var capacity = 0;
				var context = new Asn1BerDecodeContext(buffer, elemLength);

				while (!context.Expired())
				{
					var num5 = MatchTag(buffer, Asn1OctetString.Tag);

					if (num5 <= 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					capacity += num5;
					StringBuffer.EnsureCapacity(capacity);

					while (num5 > 0)
					{
						num2 = buffer.Read();

						if (num2 == -1)
						{
							throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
						}

						StringBuffer.Append((char)num2);
						num5--;
					}
				}

				if (elemLength == Asn1Status.IndefiniteLength)
				{
					MatchTag(buffer, Asn1Tag.Eoc);
				}
			}

			Value = StringBuffer.ToString();
			buffer.TypeCode = (short)tag.IdCode;
		}

		protected virtual int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging, Asn1Tag tag)
		{
			var length = Value.Length;
			buffer.Copy(Value);

			if (explicitTagging)
			{
				length += buffer.EncodeTagAndLength(tag, length);
			}

			return length;
		}

		public override bool Equals(object value)
		{
			var str = value as Asn1CharString;

			if (str == null)
			{
				return false;
			}

			return Equals(str.Value);
		}

		public bool Equals(string value)
		{
			return Value.Equals(value);
		}

		public override int GetHashCode()
		{
			return (Value != null) ? Value.GetHashCode() : base.GetHashCode();
		}

		public override string ToString()
		{
			return Value;
		}
	}
}