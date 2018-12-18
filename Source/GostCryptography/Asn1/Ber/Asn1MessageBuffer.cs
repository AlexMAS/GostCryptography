using System;
using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public abstract class Asn1MessageBuffer
	{
		public abstract Stream GetInputStream();

		public static void HexDump(Stream ins)
		{
			var outs = new StreamWriter(Console.OpenStandardOutput(), Console.Out.Encoding)
					   {
						   AutoFlush = true
					   };

			HexDump(ins, outs);
		}

		public static void HexDump(Stream ins, StreamWriter outs)
		{
		}
	}
}