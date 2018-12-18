using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1BmpString : Asn1CharString
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, BmpStringTypeCode);

		public Asn1BmpString()
			: base(BmpStringTypeCode)
		{
		}

		public Asn1BmpString(string data)
			: base(data, BmpStringTypeCode)
		{
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			var len = elemLength;
			var sb = new StringBuilder();

			var lastTag = buffer.LastTag;

			if ((lastTag == null) || !lastTag.Constructed)
			{
				sb.EnsureCapacity(elemLength / 2);
				ReadSegment(buffer, sb, len);
			}
			else
			{
				var capacity = 0;
				var context = new Asn1BerDecodeContext(buffer, elemLength);

				while (!context.Expired())
				{
					var num3 = MatchTag(buffer, Asn1OctetString.Tag);

					if (num3 <= 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					capacity += num3;
					sb.EnsureCapacity(capacity);
					ReadSegment(buffer, sb, num3);
				}

				if (elemLength == Asn1Status.IndefiniteLength)
				{
					MatchTag(buffer, Asn1Tag.Eoc);
				}
			}

			Value = sb.ToString();
			buffer.TypeCode = BmpStringTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var length = Value.Length;

			for (var i = length - 1; i >= 0; --i)
			{
				var num3 = Value[i];
				var num = num3 % 0x100;
				var num2 = num3 / 0x100;

				buffer.Copy((byte)num);
				buffer.Copy((byte)num2);
			}

			length *= 2;

			if (explicitTagging)
			{
				length += buffer.EncodeTagAndLength(Tag, length);
			}

			return length;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeBmpString(Value, explicitTagging, Tag);
		}

		private static void ReadSegment(Asn1DecodeBuffer buffer, StringBuilder sb, int len)
		{
			if ((len % 2) != 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			while (len > 0)
			{
				var num = buffer.Read();

				if (num == -1)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
				}

				var num2 = num * 0x100;
				len--;
				num = buffer.Read();

				if (num == -1)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
				}

				num2 += num;
				len--;
				sb.Append((char)num2);
			}
		}
	}
}