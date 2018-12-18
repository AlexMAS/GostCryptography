using GostCryptography.Asn1.Ber;

namespace GostCryptography.Asn1.Gost.PublicKey
{
	public sealed class AlgorithmId
	{
		public AlgorithmId(Asn1ObjectIdentifier id, Asn1Type type)
		{
			Id = id;
			Type = type;
		}


		public Asn1ObjectIdentifier Id { get; }

		public Asn1Type Type { get; }
	}
}