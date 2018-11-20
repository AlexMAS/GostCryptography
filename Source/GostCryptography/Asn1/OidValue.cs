using System.Linq;
using System.Security.Cryptography;

namespace GostCryptography.Asn1
{
	public sealed class OidValue
	{
		public static readonly OidValue Null = new OidValue("", new int[] { });


		private OidValue(string value, int[] items)
		{
			Value = value;
			Items = items;
		}


		public static OidValue FromString(string value)
		{
			var items = value.Split('.').Select(int.Parse).ToArray();
			return new OidValue(value, items);
		}

		public static OidValue FromArray(int[] items)
		{
			string value = string.Join(".", items);
			return new OidValue(value, items);
		}


		public string Value { get; }

		public int[] Items { get; }


		public override int GetHashCode()
		{
			if (Items == null)
			{
				return 0;
			}

			var result = 1;

			foreach (var item in Items)
			{
				result = 31 * result + item.GetHashCode();
			}

			return result;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}

			if (!(obj is OidValue))
			{
				return false;
			}

			var other = (OidValue)obj;

			if (Items == other.Items)
			{
				return true;
			}

			if (Items == null || other.Items == null)
			{
				return false;
			}

			if (Items.Length != other.Items.Length)
			{
				return false;
			}

			for (var i = 0; i < Items.Length; ++i)
			{
				if (Items[i] != other.Items[i])
				{
					return false;
				}
			}

			return true;
		}

		public override string ToString()
		{
			return Value;
		}


		public Oid ToOid()
		{
			return new Oid(Value);
		}
	}
}