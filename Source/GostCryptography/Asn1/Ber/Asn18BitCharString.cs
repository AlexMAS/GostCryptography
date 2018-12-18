using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn18BitCharString : Asn1CharString
	{
		public const int BitsPerCharA = 8;
		public const int BitsPerCharU = 7;

		protected internal Asn18BitCharString(short typeCode)
			: base(typeCode)
		{
		}

		protected internal Asn18BitCharString(string data, short typeCode)
			: base(data, typeCode)
		{
		}
	}
}