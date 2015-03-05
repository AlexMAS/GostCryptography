using GostCryptography.Asn1.Ber;

namespace GostCryptography.Asn1.PKI.Explicit88
{
	sealed class AlgorithmId
	{
		public readonly Asn1Type Type;
		public readonly Asn1ObjectIdentifier Id;

		public AlgorithmId(Asn1ObjectIdentifier id, Asn1Type type)
		{
			Id = id;
			Type = type;
		}
	}
}