using System;
using System.IO;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1OctetString : Asn1Type, IComparable
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, OctetStringTypeCode);

		[NonSerialized]
		public byte[] Value;

		public Asn1OctetString()
		{
			Value = null;
		}

		public Asn1OctetString(byte[] data)
		{
			Value = data;
		}

		public Asn1OctetString(string value)
		{
			Value = string.IsNullOrEmpty(value) ? new byte[0] : Asn1Value.ParseString(value);
		}

		public Asn1OctetString(byte[] data, int offset, int nbytes)
		{
			Value = new byte[nbytes];

			if (data != null)
			{
				Array.Copy(data, offset, Value, 0, nbytes);
			}
		}

		public override int Length
		{
			get { return Value.Length; }
		}

		public virtual int CompareTo(object octstr)
		{
			var value = ((Asn1OctetString)octstr).Value;
			var num = (Value.Length < value.Length) ? Value.Length : value.Length;

			for (var i = 0; i < num; i++)
			{
				var num2 = Value[i] & 0xff;
				var num3 = value[i] & 0xff;

				if (num2 < num3)
				{
					return -1;
				}

				if (num2 > num3)
				{
					return 1;
				}
			}

			if (Value.Length == value.Length)
			{
				return 0;
			}

			if (Value.Length < value.Length)
			{
				return -1;
			}

			return 1;
		}

		private void AllocByteArray(int nbytes)
		{
			if (Value == null)
			{
				Value = new byte[nbytes];
			}
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			var lastTag = buffer.LastTag;

			if ((lastTag == null) || !lastTag.Constructed)
			{
				if (elemLength < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
				}

				Value = new byte[elemLength];

				if (elemLength != 0)
				{
					buffer.Read(Value);
				}
			}
			else
			{
				var nbytes = 0;
				var offset = 0;
				var context = new Asn1BerDecodeContext(buffer, elemLength);

				while (!context.Expired())
				{
					var num2 = MatchTag(buffer, Tag);

					if (num2 <= 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					nbytes += num2;

					if (offset == 0)
					{
						Value = new byte[nbytes];
					}
					else
					{
						ReAllocByteArray(nbytes);
					}

					buffer.Read(Value, offset, num2);
					offset = nbytes;
				}

				if (elemLength == Asn1Status.IndefiniteLength)
				{
					MatchTag(buffer, Asn1Tag.Eoc);
				}
			}

			buffer.TypeCode = OctetStringTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (Value == null)
			{
				Value = new byte[0];
			}

			var length = Value.Length;

			if (length != 0)
			{
				buffer.Copy(Value);
			}

			if (explicitTagging)
			{
				length += buffer.EncodeTagAndLength(Tag, length);
			}

			return length;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeOctetString(Value, explicitTagging, Tag);
		}

		public bool Equals(byte[] value)
		{
			if (value.Length != Value.Length)
			{
				return false;
			}

			for (var i = 0; i < value.Length; i++)
			{
				if (value[i] != Value[i])
				{
					return false;
				}
			}

			return true;
		}

		public override bool Equals(object value)
		{
			var str = value as Asn1OctetString;

			return (str != null) && Equals(str.Value);
		}

		public override int GetHashCode()
		{
			return (Value != null) ? Value.GetHashCode() : base.GetHashCode();
		}

		private void ReAllocByteArray(int nbytes)
		{
			var value = Value;
			Value = new byte[nbytes];

			if (value != null)
			{
				Array.Copy(value, 0, Value, 0, value.Length);
			}
		}

		public virtual Stream ToInputStream()
		{
			return new MemoryStream(Value, 0, Value.Length);
		}

		public override string ToString()
		{
			var str = new StringBuilder("").ToString();

			if (Value != null)
			{
				foreach (var b in Value)
				{
					str = str + Asn1Util.ToHexString(b);
				}
			}

			return str;
		}
	}
}