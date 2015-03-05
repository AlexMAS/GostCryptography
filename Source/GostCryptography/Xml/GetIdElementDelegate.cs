using System.Xml;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Возвращает XML-элемент с указанным идентификатором.
	/// </summary>
	/// <param name="document">Документ для поиска идентификатора элемента.</param>
	/// <param name="idValue">Значение идентификатора элемента.</param>
	public delegate XmlElement GetIdElementDelegate(XmlDocument document, string idValue);
}