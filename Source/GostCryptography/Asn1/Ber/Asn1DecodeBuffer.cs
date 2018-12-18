using System;
using System.Collections;
using System.IO;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public abstract class Asn1DecodeBuffer : Asn1MessageBuffer
	{
		private readonly ArrayList _captureBufferList;
		private int _byteCount;
		private Stream _inputStream;
		private long _markedPosition;
		private ArrayList _namedEventHandlerList;
		private int _savedByteCount;
		private short _typeCode;
		private int[] _oidBuffer;

		protected Asn1DecodeBuffer(byte[] msgdata)
		{
			_namedEventHandlerList = new ArrayList();
			_captureBufferList = new ArrayList(5);

			SetInputStream(msgdata, 0, msgdata.Length);
		}

		protected Asn1DecodeBuffer(Stream inputStream)
		{
			_namedEventHandlerList = new ArrayList();
			_captureBufferList = new ArrayList(5);

			_inputStream = inputStream.CanSeek ? inputStream : new BufferedStream(inputStream);

			Init();
		}

		public virtual int ByteCount
		{
			get { return _byteCount; }
		}

		public virtual Asn1DecodeBuffer EventHandlerList
		{
			set { _namedEventHandlerList = value._namedEventHandlerList; }
		}

		public virtual short TypeCode
		{
			set { _typeCode = value; }
		}

		public virtual void AddCaptureBuffer(MemoryStream buffer)
		{
			_captureBufferList.Add(buffer);
		}

		public virtual void AddNamedEventHandler(IAsn1NamedEventHandler handler)
		{
			_namedEventHandlerList.Add(handler);
		}

		public virtual void Capture(int nbytes)
		{
			for (var i = 0; i < nbytes; i++)
			{
				var num = _inputStream.ReadByte();

				if (num == -1)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
				}

				foreach (MemoryStream s in _captureBufferList)
				{
					s.WriteByte((byte)num);
				}

				_byteCount++;
			}
		}

		public virtual long DecodeIntValue(int length, bool signExtend)
		{
			return Asn1RunTime.DecodeIntValue(this, length, signExtend);
		}

		public virtual int[] DecodeOidContents(int llen)
		{
			var index = 0;

			if (_oidBuffer == null)
			{
				_oidBuffer = new int[0x80];
			}

			while (llen > 0)
			{
				int num;

				if (index >= 0x80)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
				}

				_oidBuffer[index] = 0;

				do
				{
					num = ReadByte();
					_oidBuffer[index] = (_oidBuffer[index] * 0x80) + (num & 0x7f);
					llen--;
				}
				while ((num & 0x80) != 0);

				if (index == 0)
				{
					var num3 = _oidBuffer[0];

					_oidBuffer[0] = ((num3 / 40) >= 2) ? 2 : (num3 / 40);
					_oidBuffer[1] = (_oidBuffer[0] == 2) ? (num3 - 80) : (num3 % 40);

					index = 2;
				}
				else
				{
					index++;
				}
			}

			if (llen != 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			var destinationArray = new int[index];
			Array.Copy(_oidBuffer, 0, destinationArray, 0, index);
			return destinationArray;
		}

		public virtual int[] DecodeRelOidContents(int llen)
		{
			var index = 0;

			if (_oidBuffer == null)
			{
				_oidBuffer = new int[0x80];
			}

			while (llen > 0)
			{
				int num;

				if (index >= 0x80)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
				}

				_oidBuffer[index] = 0;

				do
				{
					num = ReadByte();
					_oidBuffer[index] = (_oidBuffer[index] * 0x80) + (num & 0x7f);
					llen--;
				}
				while ((num & 0x80) != 0);

				index++;
			}

			if (llen != 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			var destinationArray = new int[index];
			Array.Copy(_oidBuffer, 0, destinationArray, 0, index);
			return destinationArray;
		}

		public override Stream GetInputStream()
		{
			return _inputStream;
		}

		public virtual void HexDump()
		{
			HexDump(_inputStream);
		}

		protected virtual void Init()
		{
			_byteCount = 0;
			_markedPosition = 0L;
			_savedByteCount = 0;
		}

		public virtual void InvokeCharacters(string svalue)
		{
			var enumerator = _namedEventHandlerList.GetEnumerator();

			while (enumerator.MoveNext())
			{
				((IAsn1NamedEventHandler)enumerator.Current).Characters(svalue, _typeCode);
			}
		}

		public virtual void InvokeEndElement(string name, int index)
		{
			var enumerator = _namedEventHandlerList.GetEnumerator();

			while (enumerator.MoveNext())
			{
				((IAsn1NamedEventHandler)enumerator.Current).EndElement(name, index);
			}
		}

		public virtual void InvokeStartElement(string name, int index)
		{
			var enumerator = _namedEventHandlerList.GetEnumerator();

			while (enumerator.MoveNext())
			{
				((IAsn1NamedEventHandler)enumerator.Current).StartElement(name, index);
			}
		}

		public virtual void Mark()
		{
			_savedByteCount = _byteCount;
			_markedPosition = _inputStream.Position;
		}

		public virtual int Read()
		{
			var num = _inputStream.ReadByte();

			if (num == -1)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
			}

			foreach (MemoryStream s in _captureBufferList)
			{
				s.WriteByte((byte)num);
			}

			_byteCount++;

			return num;
		}

		public virtual void Read(byte[] buffer)
		{
			Read(buffer, 0, buffer.Length);
		}

		public virtual void Read(byte[] buffer, int offset, int nbytes)
		{
			var count = nbytes;
			var num3 = offset;

			while (count > 0)
			{
				var num = _inputStream.Read(buffer, num3, count);

				if (num <= 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
				}

				num3 += num;
				count -= num;
			}

			foreach (MemoryStream s in _captureBufferList)
			{
				s.Write(buffer, offset, nbytes);
			}

			_byteCount += nbytes;
		}

		public abstract int ReadByte();

		public virtual void RemoveCaptureBuffer(MemoryStream buffer)
		{
			for (var i = 0; i < _captureBufferList.Count; i++)
			{
				if (buffer == _captureBufferList[i])
				{
					_captureBufferList.RemoveAt(i);
					return;
				}
			}
		}

		public virtual void Reset()
		{
			try
			{
				_inputStream.Position = _markedPosition;
				_byteCount = _savedByteCount;
			}
			catch (Exception)
			{
			}
		}

		public virtual void SetInputStream(byte[] msgdata, int offset, int length)
		{
			_inputStream = new MemoryStream(msgdata, offset, length);

			Init();
		}

		public virtual long Skip(long nbytes)
		{
			var inputStream = _inputStream;
			var position = inputStream.Position;

			return (inputStream.Seek(nbytes, SeekOrigin.Current) - position);
		}
	}
}