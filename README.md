# Discription
it  is  a  BBS04 signature  lib for  golang 
# How  to  install  the  lib
## First :install  the  GMP
This package must be compiled using cgo. It also requires the installation of GMP and PBC. During the build process, this package will attempt to include <gmp.h> and <pbc/pbc.h>, and then dynamically link to GMP and PBC.

Most systems include a package for GMP. To install GMP in Debian / Ubuntu:

`sudo apt-get install libgmp-dev`

For an RPM installation with YUM:

`sudo yum install gmp-devel`

For installation with Fink (http://www.finkproject.org/) on Mac OS X:

`sudo fink install gmp gmp-shlibs`

For more information or to compile from source, visit https://gmplib.org/

## Second:install the PBC 
To install the PBC library, download the appropriate files for your system from https://crypto.stanford.edu/pbc/download.html. PBC has three dependencies: the gcc compiler, flex (http://flex.sourceforge.net/), and bison (https://www.gnu.org/software/bison/). See the respective sites for installation instructions. Most distributions include packages for these libraries. For example, in Debian / Ubuntu:

`sudo apt-get install build-essential flex bison`

The PBC source can be compiled and installed using the usual GNU Build System:
```
./configure
make
sudo make install
```

After installing, you may need to rebuild the search path for libraries:

`sudo ldconfig`

It is possible to install the package on Windows through the use of MinGW and MSYS. MSYS is required for installing PBC, while GMP can be installed through a package. Based on your MinGW installation, you may need to add` "-I/usr/local/include"` to CPPFLAGS and `"-L/usr/local/lib" `to LDFLAGS when building PBC. Likewise, you may need to add these options to` CGO_CPPFLAGS `and` CGO_LDFLAGS` when installing this package. 

and  then  install the  golang  pbc  lib 

` go  get  github.com/Nik-U/pbc`

## Third: install  the BBS04 signature  golang  lib
download the bbs04  signature  lib  

` go  get  go  get  github.com/yunfeiyangbuaa/BBS04_signature`

and  imprt in your code 

`import "github.com/yunfeiyangbuaa/BBS04_signature"`
#  How to use
##   Exmple
 ```
func  main(){
	params:=pbc.GenerateA(160,512)
	pairing:=params.NewPairing()
	g1:=pairing.NewG1().Rand()
	g2:=pairing.NewG2().Rand()
	priv:=GenerateGroup(g1,g2 ,pairing)
    //genarate  new  member
	member:=priv.NewMember()
	//generate  new  cert
	cert:=priv.Cert(member.u_)
	fmt.Println(cert.A.String())

	member1:=priv.NewMember()
	cert1:=priv.Cert(member1.u_)
	fmt.Println(cert1.A.String())

	//verify  cert
	member.Verify_cert(cert)
	member1.Verify_cert(cert1)
	//generate   mima
	c1:=pairing.NewG1().Rand()
	c2:=pairing.NewG1().Rand()
	c3:=pairing.NewG1().Mul(c1,c2)
	//generate  signature
	sig:=member.Sign(cert,c1,c2,c3)
	sig1:=member1.Sign(cert1,c1,c2,c3)
	//verify    signature
	priv.Group.Verify_sign(sig,member.h_)
	priv.Group.Verify_sign(sig1,member1.h_)
	priv.open(sig)
	priv.open(sig1)
}

 ```
## Function 
```
func (member *MemberKey) Verify_cert(cert *Cert)bool
func GenerateGroup(g_1,g_2  *pbc.Element,pairing_ *pbc.Pairing) (*PrivateKey)
func (g *Group) precompute() 
func (priv *PrivateKey) NewMember() (*MemberKey)
func (priv *PrivateKey)Cert(u3  *pbc.Element)(*Cert)
func (priv  *PrivateKey)open(sig  *Sig)*pbc.Element
func (g *Group) Verify_sign(sig  *Sig,h3 *pbc.Element) bool
func (mem *MemberKey) Sign(cert  *Cert,c1,c2,c3  *pbc.Element) (*Sig) 

 ```
