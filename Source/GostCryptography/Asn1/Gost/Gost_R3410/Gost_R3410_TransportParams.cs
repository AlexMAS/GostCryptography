using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.PublicKey;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public sealed class Gost_R3410_TransportParams : Asn1Type
	{
		public Gost_28147_89_ParamSet EncryptionParamSet { get; set; }

		public SubjectPublicKeyInfo EphemeralPublicKey { get; set; }

		public Asn1OctetString Ukm { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			EncryptionParamSet = null;
			EphemeralPublicKey = null;
			Ukm = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptionParamSet = new Gost_28147_89_ParamSet();
			EncryptionParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0x80, 0x20, EocTypeCode, parsedLen, true))
			{
				EphemeralPublicKey = new SubjectPublicKeyInfo();
				EphemeralPublicKey.Decode(buffer, false, parsedLen.Value);
			}

			if (!context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			Ukm = new Asn1OctetString();
			Ukm.Decode(buffer, true, parsedLen.Value);

			if (Ukm.Length != 8)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Ukm.Length), Ukm.Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (Ukm.Length != 8)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Ukm.Length), Ukm.Length);
			}

			len += Ukm.Encode(buffer, true);

			if (EphemeralPublicKey != null)
			{
				var epkLength = EphemeralPublicKey.Encode(buffer, false);

				len += epkLength;
				len += buffer.EncodeTagAndLength(0x80, 0x20, EocTypeCode, epkLength);
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