using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public sealed class Gost_28147_89_BlobParams : Asn1Type
	{
		public Gost_28147_89_ParamSet EncryptionParamSet { get; set; }

		public Asn1OpenExt ExtElement { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			EncryptionParamSet = null;
			ExtElement = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptionParamSet = new Gost_28147_89_ParamSet();
			EncryptionParamSet.Decode(buffer, true, parsedLen.Value);

			if (!context.Expired())
			{
				if (buffer.PeekTag().Equals(0, 0, ObjectIdentifierTypeCode))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1SeqOrderException);
				}

				ExtElement = new Asn1OpenExt();

				while (!context.Expired())
				{
					ExtElement.DecodeComponent(buffer);
				}
			}
			else
			{
				ExtElement = null;
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (ExtElement != null)
			{
				len += ExtElement.Encode(buffer, false);
			}

			len += EncryptionParamSet.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}
	}
}