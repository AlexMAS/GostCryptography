using System;
using System.Security.Cryptography;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	class Asn1ObjectIdentifier : Asn1Type
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, ObjectIdentifierTypeCode);

		[NonSerialized]
		public int[] Value;

		public Asn1ObjectIdentifier()
		{
			Value = null;
		}

		public Asn1ObjectIdentifier(int[] value)
		{
			Value = value;
		}

		public virtual void Append(int[] value2)
		{
			var destinationIndex = 0;

			if (Value == null)
			{
				Value = new int[value2.Length];
			}
			else
			{
				var value = Value;
				destinationIndex = Value.Length;
				Value = new int[Value.Length + value2.Length];
				Array.Copy(value, 0, Value, 0, value.Length);
			}

			Array.Copy(value2, 0, Value, destinationIndex, value2.Length);
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var llen = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;

			if (llen <= 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			Value = buffer.DecodeOidContents(llen);
			buffer.TypeCode = ObjectIdentifierTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (((Value.Length < 2) || (Value[0] > 2)) || ((Value[0] != 2) && (Value[1] > 0x27)))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 0;

			for (var i = Value.Length - 1; i >= 1; i--)
			{
				len += buffer.EncodeIdentifier((i == 1) ? ((Value[0] * 40) + Value[1]) : Value[i]);
			}

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			int num;

			if (((Value.Length < 2) || (Value[0] > 2)) || ((Value[0] != 2) && (Value[1] > 0x27)))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 1;

			for (num = 2; num < Value.Length; num++)
			{
				len += Asn1RunTime.GetIdentBytesCount(Value[num]);
			}

			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			outs.EncodeLength(len);
			var ident = (Value[0] * 40) + Value[1];
			outs.EncodeIdentifier(ident);

			for (num = 2; num < Value.Length; num++)
			{
				outs.EncodeIdentifier(Value[num]);
			}
		}

		public override bool Equals(object value)
		{
			var identifier = value as Asn1ObjectIdentifier;

			if (identifier == null)
			{
				return false;
			}

			if (identifier.Value.Length != Value.Length)
			{
				return false;
			}

			for (var i = 0; i < Value.Length; i++)
			{
				if (Value[i] != identifier.Value[i])
				{
					return false;
				}
			}

			return true;
		}

		public override int GetHashCode()
		{
			return (Value != null) ? Value.GetHashCode() : base.GetHashCode();
		}

		public override string ToString()
		{
			var str = new StringBuilder("{ ").ToString();

			foreach (var v in Value)
			{
				str = str + Convert.ToString(v) + " ";
			}

			return (str + "}");
		}


		public static Asn1ObjectIdentifier FromOidString(string value)
		{
			Asn1ObjectIdentifier identifier;

			if (value == null)
			{
				return null;
			}

			var num = 1;

			foreach (var ch in value)
			{
				if (ch == '.')
				{
					num++;
				}
			}

			var numArray = new int[num];
			var num2 = 0;
			num = 0;

			while (num2 < value.Length)
			{
				var c = value[num2];

				if (!char.IsDigit(c))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EncodeErrorWithValue, typeof(Asn1ObjectIdentifier).FullName, value);
				}

				var num3 = 0;

				while (num2 < value.Length)
				{
					c = value[num2++];

					if (c == '.')
					{
						break;
					}

					if (!char.IsDigit(c))
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1EncodeErrorWithValue, typeof(Asn1ObjectIdentifier).FullName, value);
					}

					num3 = ((num3 * 10) + c) - 48;
				}

				numArray[num++] = num3;
			}

			try
			{
				identifier = new Asn1ObjectIdentifier(numArray);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, typeof(Asn1ObjectIdentifier).FullName);
			}

			return identifier;
		}

		public static string ToOidString(Asn1ObjectIdentifier id)
		{
			if (id != null)
			{
				var builder = new StringBuilder(id.Value.Length * 10);

				foreach (var num in id.Value)
				{
					builder.Append("." + num);
				}

				return builder.ToString().Substring(1);
			}

			return null;
		}
	}
}