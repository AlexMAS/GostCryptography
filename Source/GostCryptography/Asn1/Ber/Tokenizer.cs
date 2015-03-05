using System;
using System.Collections;

namespace GostCryptography.Asn1.Ber
{
	class Tokenizer : IEnumerator
	{
		private readonly char[] _chars;
		private readonly bool _includeDelims;
		private long _currentPos;
		private string _delimiters;

		public Tokenizer(string source)
		{
			_delimiters = " \t\n\r\f";
			_chars = source.ToCharArray();
		}

		public Tokenizer(string source, string delimiters)
			: this(source)
		{
			_delimiters = delimiters;
		}

		public Tokenizer(string source, string delimiters, bool includeDelims)
			: this(source, delimiters)
		{
			_includeDelims = includeDelims;
		}

		public int Count
		{
			get
			{
				int num3;
				var currentPos = _currentPos;
				var num2 = 0;

				try
				{
					while (true)
					{
						NextToken();
						num2++;
					}
				}
				catch (ArgumentOutOfRangeException)
				{
					_currentPos = currentPos;
					num3 = num2;
				}

				return num3;
			}
		}

		public bool MoveNext()
		{
			return HasMoreTokens();
		}

		public void Reset()
		{
		}

		public object Current
		{
			get { return NextToken(); }
		}

		public bool HasMoreTokens()
		{
			var currentPos = _currentPos;

			try
			{
				NextToken();
			}
			catch (ArgumentOutOfRangeException)
			{
				return false;
			}
			finally
			{
				_currentPos = currentPos;
			}

			return true;
		}

		public string NextToken()
		{
			return NextToken(_delimiters);
		}

		public string NextToken(string delimiters)
		{
			_delimiters = delimiters;

			var array = delimiters.ToCharArray();

			if (_currentPos == _chars.Length)
			{
				throw ExceptionUtility.ArgumentOutOfRange("delimiters");
			}

			if ((Array.IndexOf(array, _chars[(int)((IntPtr)_currentPos)], 0, array.Length) != -1) && _includeDelims)
			{
				long num;
				_currentPos = (num = _currentPos) + 1L;

				return ("" + _chars[(int)((IntPtr)num)]);
			}

			return NextToken(delimiters.ToCharArray());
		}

		private string NextToken(char[] delimiters)
		{
			var str = "";
			var currentPos = _currentPos;

			while (Array.IndexOf(delimiters, _chars[(int)((IntPtr)_currentPos)], 0, delimiters.Length) != -1)
			{
				if ((_currentPos += 1L) == _chars.Length)
				{
					_currentPos = currentPos;

					throw ExceptionUtility.ArgumentOutOfRange("delimiters");
				}
			}

			while (Array.IndexOf(delimiters, _chars[(int)((IntPtr)_currentPos)], 0, delimiters.Length) == -1)
			{
				str = str + _chars[(int)((IntPtr)_currentPos)];

				if ((_currentPos += 1L) == _chars.Length)
				{
					return str;
				}
			}

			return str;
		}

		public string RemainingString()
		{
			if ((_chars != null) && (_currentPos < _chars.Length))
			{
				return new string(_chars, (int)_currentPos, _chars.Length);
			}

			return null;
		}
	}
}