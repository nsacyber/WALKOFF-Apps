# -*- encoding: utf-8 -*-
"""
pyvas utilities
~~~~~~~~~~~~~~~
"""

import collections
import six
from lxml import etree


def dict_to_lxml(root, dct):
    """Convert dict to ElementTree"""
    try:
        root = six.text_type(root)
    except Exception:
        raise TypeError("root must be a string")

    def inner_dict_to_xml(parent, dict_item):
        """Recursive dict to ElementTree conversion"""
        if isinstance(dict_item, dict):
            for tag, child in six.iteritems(dict_item):
                if six.text_type(tag) == '#text':
                    parent.text = six.text_type(child)
                elif tag.startswith("@"):
                    # Use @tag to set attributes
                    # print(tag)
                    parent.set(tag[1:], child)
                else:
                    elem = etree.Element(tag)
                    parent.append(elem)
                    inner_dict_to_xml(elem, child)

        elif dict_item is not None:
            parent.text = six.text_type(dict_item)

    root = etree.Element(root)
    inner_dict_to_xml(root, dct)
    return root


def lxml_to_dict(tree, strip_root=False):
    """Convert XML ElementTree to dictionary"""
    try:
        dct = {tree.tag: {} if tree.attrib else None}
    except AttributeError:
        raise TypeError("tree must be an XML ElementTree")

    children = list(tree)
    if children:
        default_dict = collections.defaultdict(list)
        for child in [lxml_to_dict(child) for child in children]:
            for key, value in six.iteritems(child):
                default_dict[key].append(value)
        dct = {tree.tag: {key: value[0] if len(value) == 1 else value
                          for key, value in six.iteritems(default_dict)}}
    if tree.attrib:
        dct[tree.tag].update(("@" + key, value)
                             for key, value in six.iteritems(tree.attrib))
    if tree.text:
        text = tree.text.strip()
        if children or tree.attrib:
            dct[tree.tag]["#text"] = text
        else:
            dct[tree.tag] = text

    if strip_root:
        return list(dct.values())[0]

    return dct
