namespace GostCryptography.Asn1.Ber
{
	public interface IAsn1TaggedEventHandler
	{
		void Contents(byte[] data);
		void EndElement(Asn1Tag tag);
		void StartElement(Asn1Tag tag, int len, byte[] tagLenBytes);
	}
}