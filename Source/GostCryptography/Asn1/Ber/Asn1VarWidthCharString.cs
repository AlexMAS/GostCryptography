using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1VarWidthCharString : Asn1CharString
	{
		public const int BitsPerCharA = 8;
		public const int BitsPerCharU = 8;

		protected internal Asn1VarWidthCharString(short typeCode)
			: base(typeCode)
		{
		}

		protected internal Asn1VarWidthCharString(string data, short typeCode)
			: base(data, typeCode)
		{
		}
	}
}