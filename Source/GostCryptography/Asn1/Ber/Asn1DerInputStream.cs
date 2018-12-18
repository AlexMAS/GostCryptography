using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1DerInputStream : Asn1DerDecodeBuffer, IAsn1InputStream
	{
		public Asn1DerInputStream(Stream inputStream)
			: base(inputStream)
		{
		}

		public virtual int Available()
		{
			var inputStream = GetInputStream();

			if (inputStream != null)
			{
				var num = inputStream.Length - inputStream.Position;
				return (int)num;
			}

			return 0;
		}

		public virtual void Close()
		{
			var inputStream = GetInputStream();

			if (inputStream != null)
			{
				inputStream.Close();
			}
		}

		public virtual bool MarkSupported()
		{
			var inputStream = GetInputStream();

			return ((inputStream != null) && inputStream.CanSeek);
		}
	}
}