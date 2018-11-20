using System;
using System.IO;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1Type : IAsn1Type
	{
		public const short EocTypeCode = 0;
		public const short BooleanTypeCode = 1;
		public const short BigIntegerTypeCode = 2;
		public const short BitStringTypeCode = 3;
		public const short OctetStringTypeCode = 4;
		public const short NullTypeCode = 5;
		public const short ObjectIdentifierTypeCode = 6;
		public const short ObjectDescriptorTypeCode = 7;
		public const short ExternalTypeCode = 8;
		public const short RealTypeCode = 9;
		public const short EnumeratedTypeCode = 10;
		public const short Utf8StringTypeCode = 12;
		public const short RelativeOidTypeCode = 13;
		public const short SequenceTypeCode = 0x10;
		public const short SetTypeCode = 0x11;
		public const short NumericStringTypeCode = 0x12;
		public const short PrintableStringTypeCode = 0x13;
		public const short T61StringTypeCode = 20;
		public const short VideoTexStringTypeCode = 0x15;
		public const short Ia5StringTypeCode = 0x16;
		public const short UtcTimeTypeCode = 0x17;
		public const short GeneralTimeTypeCode = 0x18;
		public const short GraphicStringTypeCode = 0x19;
		public const short VisibleStringTypeCode = 0x1a;
		public const short GeneralStringTypeCode = 0x1b;
		public const short UniversalStringTypeCode = 0x1c;
		public const short BmpStringTypeCode = 30;
		public const short OpenTypeTypeCode = 0x63;

		[NonSerialized]
		private readonly IntHolder _parsedLen = new IntHolder();

		[NonSerialized]
		private readonly Asn1Tag _parsedTag = new Asn1Tag();

		public virtual int Length
		{
			get { throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException); }
		}

		public virtual void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
		}

		public virtual int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			return 0;
		}

		public virtual void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
		}

		public virtual void Print(TextWriter outs, string varName, int level)
		{
			Indent(outs, level);
			outs.WriteLine(varName + " = " + ToString());
		}

		public virtual void Decode(Asn1BerDecodeBuffer buffer)
		{
			Decode(buffer, true, 0);
		}

		public virtual int Encode(Asn1BerEncodeBuffer buffer)
		{
			return Encode(buffer, true);
		}

		public static string GetTypeName(short typeCode)
		{
			switch (typeCode)
			{
				case EocTypeCode:
					return "EOC";
				case BooleanTypeCode:
					return "BOOLEAN";
				case BigIntegerTypeCode:
					return "INTEGER";
				case BitStringTypeCode:
					return "BIT STRING";
				case OctetStringTypeCode:
					return "OCTET STRING";
				case NullTypeCode:
					return "NULL";
				case ObjectIdentifierTypeCode:
					return "OBJECT IDENTIFIER";
				case ObjectDescriptorTypeCode:
					return "ObjectDescriptor";
				case ExternalTypeCode:
					return "EXTERNAL";
				case RealTypeCode:
					return "REAL";
				case EnumeratedTypeCode:
					return "ENUMERATED";
				case Utf8StringTypeCode:
					return "UTF8String";
				case SequenceTypeCode:
					return "SEQUENCE";
				case SetTypeCode:
					return "SET";
				case NumericStringTypeCode:
					return "NumericString";
				case PrintableStringTypeCode:
					return "PrintableString";
				case T61StringTypeCode:
					return "T61String";
				case VideoTexStringTypeCode:
					return "VideotexString";
				case Ia5StringTypeCode:
					return "IA5String";
				case UtcTimeTypeCode:
					return "UTCTime";
				case GeneralTimeTypeCode:
					return "GeneralTime";
				case GraphicStringTypeCode:
					return "GraphicString";
				case VisibleStringTypeCode:
					return "VisibleString";
				case GeneralStringTypeCode:
					return "GeneralString";
				case UniversalStringTypeCode:
					return "UniversalString";
				case BmpStringTypeCode:
					return "BMPString";
				case OpenTypeTypeCode:
					return "ANY";
			}

			return "?";
		}

		public virtual void Indent(TextWriter outs, int level)
		{
			var num2 = level * 3;

			for (var i = 0; i < num2; i++)
			{
				outs.Write(" ");
			}
		}

		protected virtual int MatchTag(Asn1BerDecodeBuffer buffer, Asn1Tag tag)
		{
			return MatchTag(buffer, tag.Class, tag.Form, tag.IdCode);
		}

		protected virtual int MatchTag(Asn1BerDecodeBuffer buffer, short tagClass, short tagForm, int tagIdCode)
		{
			if (!buffer.MatchTag(tagClass, tagForm, tagIdCode, _parsedTag, _parsedLen))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1TagMatchFailedException, new Asn1Tag(tagClass, tagForm, tagIdCode), _parsedTag, buffer.ByteCount);
			}

			return _parsedLen.Value;
		}
	}
}