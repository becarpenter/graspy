"""Quick hack to generate CBOR for arbitrary example GRASP messages"""
import grasp
import socket
import cbor


def h(s):
    return bytes.fromhex(s)


m1 =      [grasp.M_FLOOD, 12340815, h('fd89b714f3db00002000000640000001'), 210000,
            [["SRV.est", 4, 255, None ],
            [grasp.O_IPv6_LOCATOR,
                 h('fd89b714f3db00002000000640000001'), socket.IPPROTO_TCP, 443]]
        ]


m2 =    [grasp.M_FLOOD, 43215108, h('fe80000000000000c0011001feef0000'), 210000,
         [["AN_ACP", 4, 1, "IKEv2" ],
          [grasp.O_IPv6_LOCATOR,
               h('fe80000000000000c0011001feef0000'), socket.IPPROTO_UDP, 15000]],
         [["AN_ACP", 4, 1, "DTLS" ],
          [grasp.O_IPv6_LOCATOR,
               h('fe80000000000000c0011001feef0000'), socket.IPPROTO_UDP, 17000]]
       ]


print(grasp.hexit(cbor.dumps(m1)))

print(grasp.hexit(cbor.dumps(m2)))

