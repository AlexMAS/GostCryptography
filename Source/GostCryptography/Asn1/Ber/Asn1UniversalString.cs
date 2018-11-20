using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1UniversalString : Asn1Type
	{
		public const int BitsPerChar = 0x20;
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, UniversalStringTypeCode);

		[NonSerialized]
		private StringBuilder _stringBuffer;

		[NonSerialized]
		private int[] _value;


		public Asn1UniversalString()
		{
			_value = new int[0];
		}

		public Asn1UniversalString(int[] value)
		{
			_value = value;
		}

		public Asn1UniversalString(string value)
		{
			_value = new int[value.Length];

			for (var i = 0; i < value.Length; i++)
			{
				_value[i] = value[i];
			}
		}


		public override int Length
		{
			get { return _value.Length; }
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var llen = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			var idx = new IntHolder(0);
			var lastTag = buffer.LastTag;

			if ((lastTag == null) || !lastTag.Constructed)
			{
				ReadSegment(buffer, llen, idx);
			}
			else
			{
				var context = new Asn1BerDecodeContext(buffer, llen);

				while (!context.Expired())
				{
					var num2 = MatchTag(buffer, Asn1OctetString.Tag);

					if (num2 <= 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					ReadSegment(buffer, num2, idx);
				}

				if (llen == Asn1Status.IndefiniteLength)
				{
					MatchTag(buffer, Asn1Tag.Eoc);
				}
			}

			buffer.TypeCode = UniversalStringTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var length = _value.Length;

			for (var i = length - 1; i >= 0; i--)
			{
				var num3 = _value[i];

				for (var j = 0; j < 4; j++)
				{
					var num = num3 % 0x100;
					num3 /= 0x100;
					buffer.Copy((byte)num);
				}
			}

			length *= 4;

			if (explicitTagging)
			{
				length += buffer.EncodeTagAndLength(Tag, length);
			}

			return length;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeUnivString(_value, explicitTagging, Tag);
		}

		public override bool Equals(object value)
		{
			var str = value as Asn1UniversalString;

			if (str == null)
			{
				return false;
			}

			if (_value.Length != str._value.Length)
			{
				return false;
			}

			for (var i = 0; i < _value.Length; i++)
			{
				if (_value[i] != str._value[i])
				{
					return false;
				}
			}

			return true;
		}

		public override int GetHashCode()
		{
			if (_value.Length == 0)
			{
				return base.GetHashCode();
			}

			var num = 0;
			var num2 = (_value.Length > 20) ? 20 : _value.Length;

			for (var i = 0; i < num2; i++)
			{
				num ^= _value[i];
			}

			return num;
		}

		private void ReadSegment(Asn1BerDecodeBuffer buffer, int llen, IntHolder idx)
		{
			if ((llen < 0) || ((llen % 4) != 0))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			var num4 = llen / 4;

			if (_value.Length == 0)
			{
				_value = new int[num4];
			}
			else if ((idx.Value + num4) >= _value.Length)
			{
				ReallocIntArray(idx.Value + num4);
			}

			var value = idx.Value;

			while (value < (idx.Value + num4))
			{
				_value[value] = 0;

				for (var i = 0; i < 4; i++)
				{
					var num = buffer.Read();

					if (num == -1)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
					}

					_value[value] = (_value[value] * 0x100) + num;
				}

				value++;
			}

			idx.Value = value;
		}

		private void ReallocIntArray(int nint)
		{
			var value = _value;

			_value = new int[nint];

			if (value != null)
			{
				Array.Copy(value, 0, _value, 0, value.Length);
			}
		}

		public override string ToString()
		{
			if (_stringBuffer == null)
			{
				_stringBuffer = new StringBuilder();
			}

			_stringBuffer.Length = _value.Length;

			for (var i = 0; i < _value.Length; i++)
			{
				_stringBuffer[i] = (char)_value[i];
			}

			return _stringBuffer.ToString();
		}
	}
}