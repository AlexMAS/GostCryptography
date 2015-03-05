using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.GostR3410
{
	class Gost2814789KeyWrapParameters : Asn1Type
	{
		public Gost2814789ParamSet EncryptionParamSet;
		public Asn1OctetString Ukm;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptionParamSet = new Gost2814789ParamSet();
			EncryptionParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				Ukm = new Asn1OctetString();
				Ukm.Decode(buffer, true, parsedLen.Value);

				if (Ukm.Length != 8)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "Ukm.Length", Ukm.Length);
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
					throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "Ukm.Length", Ukm.Length);
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

		private void Init()
		{
			EncryptionParamSet = null;
			Ukm = null;
		}
	}
}