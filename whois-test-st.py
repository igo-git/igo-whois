import streamlit as st
import whois

from igo_whois import WhoisData

request_domain = st.text_input('Введите сайт для проверки WHOIS').lower()


if request_domain.strip() != '':
    my_whois = WhoisData(request_domain)

    py_whois = whois.whois(request_domain)
    
    st.write('**Domain:**&emsp;`' + str(py_whois.domain) + '`&emsp;`' + my_whois.getDomainName() + '`')
    st.write('**Name:**&emsp;`' + str(py_whois.name) + '`&emsp;`' + my_whois.owner['name'] + '`')
    st.write('**Person:**&emsp;`' + str(py_whois.person) + '`&emsp;`' + my_whois.owner['person'] + '`')
    st.write('**Org:**&emsp;`' + str(py_whois.org) + '`&emsp;`' + my_whois.owner['org'] + '`')
    st.write('**WHOIS server:**&emsp;`' + '\t\t' + '`&emsp;`' + my_whois.response_from + '`')

    st.divider()

    with st.expander('Raw WHOIS data'):
        st.text(my_whois.raw_info)
    # st.code(my_whois.raw_info, language=None)

    st.divider()
    st.json(my_whois.info_dict)

