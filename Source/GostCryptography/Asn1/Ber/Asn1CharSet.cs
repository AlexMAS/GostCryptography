namespace GostCryptography.Asn1.Ber
{
	public abstract class Asn1CharSet
	{
		private readonly int _aBitsPerChar;
		private readonly int _uBitsPerChar;

		protected internal Asn1CharSet(int nchars)
		{
			_uBitsPerChar = Asn1Integer.GetBitCount(nchars - 1);
			_aBitsPerChar = 1;

			while (_uBitsPerChar > _aBitsPerChar)
			{
				_aBitsPerChar = _aBitsPerChar << 1;
			}
		}

		public abstract int MaxValue { get; }

		public abstract int GetCharAtIndex(int index);

		public abstract int GetCharIndex(int charValue);

		public virtual int GetNumBitsPerChar(bool aligned)
		{
			if (!aligned)
			{
				return _uBitsPerChar;
			}

			return _aBitsPerChar;
		}
	}
}