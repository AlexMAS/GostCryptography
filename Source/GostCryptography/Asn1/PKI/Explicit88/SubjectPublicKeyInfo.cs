using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.Explicit88
{
	class SubjectPublicKeyInfo : Asn1Type
	{
		public AlgorithmIdentifier Algorithm;
		public Asn1BitString SubjectPublicKey;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0x20, 0x10, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			Algorithm = new AlgorithmIdentifier();
			Algorithm.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0, 3, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			SubjectPublicKey = new Asn1BitString();
			SubjectPublicKey.Decode(buffer, true, parsedLen.Value);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;
			len += SubjectPublicKey.Encode(buffer, true);
			len += Algorithm.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			Algorithm = null;
			SubjectPublicKey = null;
		}
	}
}