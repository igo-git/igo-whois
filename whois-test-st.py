import streamlit as st
import whois

from igo_whois import WhoisData

request_domain = st.text_input('Введите сайт для проверки WHOIS').lower()


if request_domain.strip() != '':
    my_whois = WhoisData(request_domain)

    try:
        py_whois = whois.whois(request_domain)
    except Exception:
        py_whois = None
    
    res_table  = '| | python-whois | igo-whois |\n'
    res_table += '|-------------|-----------|-----------|\n'
    res_table += '| **Domain:** | `' + (str(py_whois.domain) if py_whois is not None else 'No domain data') + '` | `' + my_whois.getDomainName() + '` |\n'
    res_table += '|**Name:**|`' + (str(py_whois.name) if py_whois is not None else 'No domain data') + '`|`' + my_whois.owner['name'] + '`|\n'
    res_table += '|**Person:**|`' + (str(py_whois.person) if py_whois is not None else 'No domain data') + '`|`' + my_whois.owner['person'] + '`|\n'
    res_table += '|**Org:**|`' + (str(py_whois.org) if py_whois is not None else 'No domain data') + '`|`' + my_whois.owner['org'] + '`|\n'
    res_table += '|**WHOIS server:**| &mdash; | `' + my_whois.response_from + '`|\n'
    st.write(res_table)

    st.divider()

    with st.expander('Raw WHOIS data'):
        st.code(my_whois.raw_info, language='yaml')

    st.divider()
    st.json(my_whois.info_dict)

