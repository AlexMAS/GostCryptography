using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public sealed class Gost_28147_89_KeyWrapParams : Asn1Type
	{
		public Gost_28147_89_ParamSet EncryptionParamSet { get; set; }

		public Asn1OctetString Ukm { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			EncryptionParamSet = null;
			Ukm = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptionParamSet = new Gost_28147_89_ParamSet();
			EncryptionParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				Ukm = new Asn1OctetString();
				Ukm.Decode(buffer, true, parsedLen.Value);

				if (Ukm.Length != 8)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Ukm.Length), Ukm.Length);
				}
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (Ukm != null)
			{
				if (Ukm.Length != 8)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Ukm.Length), Ukm.Length);
				}

				len += Ukm.Encode(buffer, true);
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