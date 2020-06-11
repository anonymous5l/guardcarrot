package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

const delta = 0x9E3779B9

func toUint32s(bytes []byte) (v []uint32) {
	length := uint32(len(bytes))
	n := length >> 2
	if length&3 != 0 {
		n++
	}
	v = make([]uint32, n)
	for i := uint32(0); i < length; i++ {
		v[i>>2] |= uint32(bytes[i]) << ((i & 3) << 3)
	}
	return v
}

func fixk(k []uint32) []uint32 {
	if len(k) < 4 {
		key := make([]uint32, 4)
		copy(key, k)
		return key
	}
	return k
}

func mx(sum uint32, y uint32, z uint32, p uint32, e uint32, k []uint32) uint32 {
	return ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[p&3^e] ^ z))
}

func decrypt(v []uint32, k []uint32) []uint32 {
	length := uint32(len(v))
	n := length - 1
	k = fixk(k)
	var y, z, sum, e, p, q uint32
	y = v[0]
	q = 6 + 52/length
	for sum = q * delta; sum != 0; sum -= delta {
		e = sum >> 2 & 3
		for p = n; p > 0; p-- {
			z = v[p-1]
			v[p] -= mx(sum, y, z, p, e, k)
			y = v[p]
		}
		z = v[n]
		v[0] -= mx(sum, y, z, p, e, k)
		y = v[0]
	}
	return v
}

func toBytes(v []uint32) []byte {
	length := uint32(len(v))
	n := length << 2
	bytes := make([]byte, n)
	for i := uint32(0); i < n; i++ {
		bytes[i] = byte(v[i>>2] >> ((i & 3) << 3))
	}
	return bytes
}

func encrypt(v []uint32, k []uint32) []uint32 {
	length := uint32(len(v))
	n := length - 1
	k = fixk(k)
	var y, z, sum, e, p, q uint32
	z = v[n]
	sum = 0
	for q = 6 + 52/length; q > 0; q-- {
		sum += delta
		e = sum >> 2 & 3
		for p = 0; p < n; p++ {
			y = v[p+1]
			v[p] += mx(sum, y, z, p, e, k)
			z = v[p]
		}
		y = v[0]
		v[n] += mx(sum, y, z, p, e, k)
		z = v[n]
	}
	return v
}

func main() {
	o, err := os.Open("GUI2.dll")
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	b, err := ioutil.ReadAll(o)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	if err := o.Close(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	// decrypt GUI.dll & Http.dll
	// key := []byte{0xBF, 0x90, 0xA1, 0x86, 0xFC, 0x57, 0xA8, 0x32, 0x89, 0x46, 0xB3, 0x1A, 0x2A, 0xFA, 0x24, 0x69}
	// decrypt GUI2.dll
	key2 := []byte{0xD2, 0xC5, 0xAA, 0x6A, 0xB6, 0xCD, 0x22, 0xCD, 0x94, 0x0A, 0x26, 0x9B, 0x10, 0xA4, 0xB5, 0x12}

	d, err := os.Create("DECRYPT_GUI2.dll")
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	// 1024为一组不能任意修改否则加密文件就不对了
	for i := 0; i < len(b); i += 0x400 {
		// 加密只需要将解密文件 调用encrypt加密回去即可
		de := toBytes(decrypt(toUint32s(b[i:i+0x400]), toUint32s(key2)))
		if _, err := d.Write(de); err != nil {
			fmt.Printf("error %s\n", err)
			return
		}
	}

	if err := d.Close(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}
}
