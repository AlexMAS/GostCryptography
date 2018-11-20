using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public sealed class Gost_R3410_KeyTransport : Asn1Type
	{
		public Gost_28147_89_EncryptedKey SessionEncryptedKey { get; set; }

		public Gost_R3410_TransportParams TransportParams { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			SessionEncryptedKey = null;
			TransportParams = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0x20, SequenceTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			SessionEncryptedKey = new Gost_28147_89_EncryptedKey();
			SessionEncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0x80, 0x20, EocTypeCode, parsedLen, true))
			{
				TransportParams = new Gost_R3410_TransportParams();
				TransportParams.Decode(buffer, false, parsedLen.Value);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (TransportParams != null)
			{
				var tpLength = TransportParams.Encode(buffer, false);

				len += tpLength;
				len += buffer.EncodeTagAndLength(0x80, 0x20, EocTypeCode, tpLength);
			}

			len += SessionEncryptedKey.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}
	}
}