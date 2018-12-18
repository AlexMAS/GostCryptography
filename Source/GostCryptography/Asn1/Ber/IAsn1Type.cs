using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public interface IAsn1Type
	{
		void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength);
		int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging);
		void Encode(Asn1BerOutputStream outs, bool explicitTagging);
		void Print(TextWriter outs, string varName, int level);
	}
}