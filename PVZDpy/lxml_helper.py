import lxml.etree

def delete_element_if_existing(
        tree: lxml.etree.ElementTree,
        xpath_remove_element: str,
        namespaces: dict):
    if len(tree.xpath(xpath_remove_element, namespaces=namespaces)) > 0:
        remove_elem = tree.xpath(xpath_remove_element, namespaces=namespaces)[0]
        remove_elem.getparent().remove(remove_elem)


def insert_if_missing(
        tree: lxml.etree.ElementTree,
        xpath_insert_parent: str,
        xpath_new_element: str,
        new_element: lxml.etree.Element,
        namespaces: dict):
    if len(tree.xpath(xpath_new_element, namespaces=namespaces)) == 0:
        parent_element = tree.xpath(xpath_insert_parent, namespaces=namespaces)
        parent_element[0].insert(0, new_element)  # append only for 1st
        pass

