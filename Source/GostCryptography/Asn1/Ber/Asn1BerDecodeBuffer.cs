using System;
using System.IO;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1BerDecodeBuffer : Asn1DecodeBuffer
	{
		private readonly IntHolder _lenHolder;
		private readonly Asn1Tag _tagHolder;

		private Asn1Tag _lastParsedTag;
		private MemoryStream _openTypeCaptureBuffer;
		private MemoryStream _parserCaptureBuffer;

		public Asn1BerDecodeBuffer(byte[] msgdata)
			: base(msgdata)
		{
			_tagHolder = new Asn1Tag();
			_lenHolder = new IntHolder();
		}

		public Asn1BerDecodeBuffer(Stream inputStream)
			: base(inputStream)
		{
			_tagHolder = new Asn1Tag();
			_lenHolder = new IntHolder();
		}

		public virtual Asn1Tag LastTag
		{
			get { return _lastParsedTag; }
		}

		public static int CalcIndefLen(byte[] data, int offset, int len)
		{
			Asn1BerDecodeBuffer buffer;

			if ((offset == 0) && (len == data.Length))
			{
				buffer = new Asn1BerDecodeBuffer(data);
			}
			else
			{
				var destinationArray = new byte[len];
				Array.Copy(data, offset, destinationArray, 0, len);
				buffer = new Asn1BerDecodeBuffer(destinationArray);
			}

			var tag = new Asn1Tag();
			var num = buffer.DecodeTagAndLength(tag);

			if (num == Asn1Status.IndefiniteLength)
			{
				var num2 = 1;
				num = 0;

				while (num2 > 0)
				{
					var byteCount = buffer.ByteCount;
					var num4 = buffer.DecodeTagAndLength(tag);
					num += buffer.ByteCount - byteCount;

					if (num4 > 0)
					{
						buffer.Skip(num4);
						num += num4;
					}
					else
					{
						if (num4 == Asn1Status.IndefiniteLength)
						{
							num2++;
							continue;
						}
						if (tag.IsEoc() && (num4 == 0))
						{
							num2--;
						}
					}
				}
			}

			return num;
		}

		public virtual int DecodeLength()
		{
			var num3 = 0;
			var num2 = Read();

			if (num2 < 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
			}

			if (num2 <= 0x80)
			{
				if (num2 == 0x80)
				{
					return Asn1Status.IndefiniteLength;
				}

				return num2;
			}

			var num = num2 & 0x7f;

			if (num > 4)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			while (num > 0)
			{
				num2 = Read();

				if (num2 < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
				}

				num3 = (num3 * 0x100) + num2;
				num--;
			}

			return num3;
		}

		public virtual byte[] DecodeOpenType()
		{
			return DecodeOpenType(true);
		}

		public virtual byte[] DecodeOpenType(bool saveData)
		{
			if (saveData)
			{
				if (_openTypeCaptureBuffer == null)
				{
					_openTypeCaptureBuffer = new MemoryStream(0x100);
				}
				else
				{
					_openTypeCaptureBuffer.Seek(0L, SeekOrigin.Begin);
					_openTypeCaptureBuffer.SetLength(0L);
				}

				AddCaptureBuffer(_openTypeCaptureBuffer);
			}

			DecodeOpenTypeElement(_tagHolder, _lenHolder, saveData);

			if (saveData)
			{
				var buffer = _openTypeCaptureBuffer.ToArray();
				RemoveCaptureBuffer(_openTypeCaptureBuffer);
				return buffer;
			}

			return null;
		}

		private void DecodeOpenTypeElement(Asn1Tag tag, IntHolder len, bool saveData)
		{
			var nbytes = DecodeTagAndLength(tag);
			var byteCount = base.ByteCount;

			if (nbytes > 0)
			{
				if (saveData)
				{
					Capture(nbytes);
				}
				else
				{
					Skip(nbytes);
				}
			}
			else if (nbytes == Asn1Status.IndefiniteLength)
			{
				MovePastEoc(saveData);
			}

			len.Value = base.ByteCount - byteCount;
		}

		public virtual void DecodeTag(Asn1Tag tag)
		{
			var num = Read();

			if (num < 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
			}

			tag.Class = (short)(num & 0xc0);
			tag.Form = (short)(num & 0x20);
			tag.IdCode = num & 0x1f;

			if (tag.IdCode == 0x1f)
			{
				var num2 = 0L;
				var num3 = 0;

				do
				{
					num = Read();

					if (num < 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, ByteCount);
					}

					num2 = (num2 * 0x80L) + (num & 0x7f);

					if ((num2 > 0x7fffffffL) || (num3++ > 8))
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidTagValue);
					}

				}
				while ((num & 0x80) != 0);

				tag.IdCode = (int)num2;
			}

			_lastParsedTag = tag;
		}

		public virtual int DecodeTagAndLength(Asn1Tag tag)
		{
			DecodeTag(tag);
			return DecodeLength();
		}

		public virtual bool MatchTag(Asn1Tag tag)
		{
			return MatchTag(tag.Class, tag.Form, tag.IdCode, null, null);
		}

		public virtual bool MatchTag(Asn1Tag tag, Asn1Tag parsedTag, IntHolder parsedLen)
		{
			return MatchTag(tag.Class, tag.Form, tag.IdCode, parsedTag, parsedLen);
		}

		public virtual bool MatchTag(short tagClass, short tagForm, int tagIdCode, Asn1Tag parsedTag, IntHolder parsedLen)
		{
			Mark();

			var tag = parsedTag ?? _tagHolder;
			var holder = parsedLen ?? _lenHolder;

			holder.Value = DecodeTagAndLength(tag);

			if (!tag.Equals(tagClass, tagForm, tagIdCode))
			{
				Reset();
				return false;
			}

			return true;
		}

		protected void MovePastEoc(bool saveData)
		{
			var tag = new Asn1Tag();
			var num = 1;

			while (num > 0)
			{
				var nbytes = DecodeTagAndLength(tag);

				if (nbytes > 0)
				{
					if (saveData)
					{
						Capture(nbytes);
					}
					else
					{
						Skip(nbytes);
					}
				}
				else if (nbytes == Asn1Status.IndefiniteLength)
				{
					num++;
				}
				else if (tag.IsEoc() && (nbytes == 0))
				{
					num--;
				}
			}
		}

		public virtual void Parse(IAsn1TaggedEventHandler handler)
		{
			if (_parserCaptureBuffer == null)
			{
				RemoveCaptureBuffer(_parserCaptureBuffer);
			}

			if (_parserCaptureBuffer == null)
			{
				_parserCaptureBuffer = new MemoryStream(0x100);
				AddCaptureBuffer(_parserCaptureBuffer);
			}
			else
			{
				_parserCaptureBuffer.Seek(0L, SeekOrigin.Begin);
				_parserCaptureBuffer.SetLength(0L);
			}

			ParseElement(handler, _tagHolder, _lenHolder);
		}

		private void ParseCons(IAsn1TaggedEventHandler handler, int len)
		{
			var tag2 = new Asn1Tag();
			var holder = new IntHolder();
			var byteCount = base.ByteCount;

			while (true)
			{
				ParseElement(handler, tag2, holder);

				if (len == Asn1Status.IndefiniteLength)
				{
					if (tag2.IsEoc() && (holder.Value == 0))
					{
						return;
					}

					continue;
				}

				if ((base.ByteCount - byteCount) >= len)
				{
					return;
				}
			}
		}

		private void ParseElement(IAsn1TaggedEventHandler handler, Asn1Tag tag, IntHolder len)
		{
			_parserCaptureBuffer.Seek(0L, SeekOrigin.Begin);
			_parserCaptureBuffer.SetLength(0L);

			len.Value = DecodeTagAndLength(tag);

			if (!tag.IsEoc() || (len.Value != 0))
			{
				handler.StartElement(tag, len.Value, _parserCaptureBuffer.ToArray());

				_parserCaptureBuffer.Seek(0L, SeekOrigin.Begin);
				_parserCaptureBuffer.SetLength(0L);

				if ((len.Value > 0) || (len.Value == Asn1Status.IndefiniteLength))
				{
					if (tag.Constructed)
					{
						ParseCons(handler, len.Value);
					}
					else
					{
						ParsePrim(handler, len.Value);
					}
				}

				handler.EndElement(tag);
			}
		}

		private void ParsePrim(IAsn1TaggedEventHandler handler, int len)
		{
			var buffer = new byte[len];
			Read(buffer);
			handler.Contents(buffer);
		}

		public virtual Asn1Tag PeekTag()
		{
			var parsedTag = new Asn1Tag();
			PeekTag(parsedTag);
			return parsedTag;
		}

		public virtual void PeekTag(Asn1Tag parsedTag)
		{
			Mark();
			DecodeTag(parsedTag);
			Reset();
		}

		public override int ReadByte()
		{
			return Read();
		}
	}
}