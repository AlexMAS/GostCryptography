using System;

using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.Explicit88
{
	class AlgorithmIdentifier : Asn1Type
	{
		public Asn1ObjectIdentifier Algorithm;
		public Asn1Type Parameters;


		public AlgorithmIdentifier()
		{
		}

		public AlgorithmIdentifier(Asn1ObjectIdentifier algorithm, Asn1OpenType parameters)
		{
			Algorithm = algorithm;
			Parameters = parameters;
		}


		private void CheckTc(bool decode)
		{
			AlgorithmId algorithmId = null;

			foreach (var alg in PkiConstants.SupportedAlgorithms)
			{
				if (alg.Id.Equals(Algorithm))
				{
					algorithmId = alg;
					break;
				}
			}

			if ((algorithmId != null) && ((decode && (Parameters != null)) && (algorithmId.Type != null)))
			{
				try
				{
					var buffer = new Asn1BerDecodeBuffer(((Asn1OpenType)Parameters).Value);
					Parameters = (Asn1Type)Activator.CreateInstance(algorithmId.Type.GetType());
					Parameters.Decode(buffer, true, 0);
					buffer.InvokeEndElement("parameters", -1);
				}
				catch (Exception exception)
				{
					Asn1Util.WriteStackTrace(exception, Console.Error);
					throw ExceptionUtility.CryptographicException(Resources.Asn1TableConstraint);
				}
			}
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, 6, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			Algorithm = new Asn1ObjectIdentifier();
			Algorithm.Decode(buffer, true, parsedLen.Value);

			if (!context.Expired())
			{
				Parameters = new Asn1OpenType();
				Parameters.Decode(buffer, true, 0);
			}

			CheckTc(true);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;
			CheckTc(false);

			if (Parameters != null)
			{
				len += Parameters.Encode(buffer, true);
			}

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
			Parameters = null;
		}
	}
}