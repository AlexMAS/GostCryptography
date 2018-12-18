using System;
using System.IO;
using System.Text;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1OpenType : Asn1OctetString
	{
		private const string EncodedDataMessage = "ENCODED DATA";

		[NonSerialized]
		private readonly Asn1EncodeBuffer _encodeBuffer;

		[NonSerialized]
		private readonly int _length;

		[NonSerialized]
		private readonly bool _textEncoding;


		public Asn1OpenType()
		{
			_length = 0;
			_textEncoding = false;
		}

		public Asn1OpenType(byte[] data)
			: base(data)
		{
			_length = 0;
			_textEncoding = false;
		}

		public Asn1OpenType(Asn1EncodeBuffer buffer)
		{
			if (buffer is Asn1BerEncodeBuffer)
			{
				_length = buffer.MsgLength;
				_encodeBuffer = buffer;
			}
			else
			{
				Value = buffer.MsgCopy;
			}

			_textEncoding = false;
		}

		public Asn1OpenType(byte[] data, int offset, int nbytes)
			: base(data, offset, nbytes)
		{
			_length = 0;
			_textEncoding = false;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			Value = buffer.DecodeOpenType();
			buffer.TypeCode = OpenTypeTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (Value == null)
			{
				return _length;
			}

			return base.Encode(buffer, false);
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			if (Value != null)
			{
				outs.Write(Value);
			}
		}

		public override string ToString()
		{
			if (Value != null)
			{
				try
				{
					return (_textEncoding ? Encoding.UTF8.GetString(Value, 0, Value.Length) : base.ToString());
				}
				catch (IOException)
				{
					return null;
				}
			}

			if (_encodeBuffer != null)
			{
				return _encodeBuffer.ToString();
			}

			return EncodedDataMessage;
		}
	}
}