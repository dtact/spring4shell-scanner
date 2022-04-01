package app

import (

	// "github.com/dutchcoders/dirbuster/vendor.bak/gopkg.in/src-d/go-git.v4/utils/ioutil"

	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"os"

	"github.com/fatih/color"
	"github.com/gosuri/uilive"
	_ "github.com/op/go-logging"
)

type fuzzer struct {
	config

	signatures map[string]string

	writer *uilive.Writer
	output *writer

	allowList [][]byte

	remoteHosts []string
	targetPaths []string
	excludeList []string

	stats Stats
}

type writer struct {
	f io.WriteCloser
	m sync.Mutex
}

func NewWriter(path string) (*writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &writer{
		f: f,
		m: sync.Mutex{},
	}, nil
}

func (w *writer) WriteLine(format string, args ...interface{}) {
	w.m.Lock()
	defer w.m.Unlock()

	fmt.Fprintln(w.f, fmt.Sprintf(format, args...))
}

func New(options ...OptionFn) (*fuzzer, error) {
	b := &fuzzer{
		config:     config{},
		signatures: map[string]string{},
	}

	b.writer = uilive.New()
	b.writer.Out = color.Output

	for k, v := range signatures {
		for _, s := range v {
			h, _ := hex.DecodeString(s)
			b.signatures[string(h)] = k
		}
	}

	for _, optionFunc := range options {
		if err := optionFunc(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

var signatures = map[string][]string{
	"1.2-rc1":        []string{"a641cbba918908242c5d9d6c624d1e15007890886ade13257837d93d2efecef7"},
	"1.2-rc2":        []string{"9218328ec3e6be246314a228c446d1d14e030197d9a40c4a5fbb22bfe79991e7"},
	"1.2.1":          []string{"3722773cecc67cde76dfb2f48a5bb50bc681ebb4a4d157243c0eace0fd2c9976"},
	"1.2.2":          []string{"4a1b6b50c8e769bdc467177e31af0a3ac682d1868e32cbc7be115bb34301fba2"},
	"1.2.3":          []string{"e03001bdbfbbcf3117440b7f4c06c614f844150d07ff1029333da6e4bf4d0156"},
	"1.2.4":          []string{"4ed90b4fc3bbe6ff16cd7a8ceb43d06cc40face9d491b6d566f410096b42eb92"},
	"1.2.5":          []string{"461736db6cadf375e8a5eb21a90b2a354722b7aa723a28ef20de826013649f02"},
	"1.2.6":          []string{"b4d103996825ca1f9b3cd70aab322e7b315108c92a4cc1105841ef0f7d32bcae"},
	"1.2.8":          []string{"473f32615143209e8bf161e01928055157669453deb76d0b9525e94d40701d75"},
	"1.2.9":          []string{"7a6e98cc30c2fcbe9cee19b10be1ffb25b249c360f6adbeb0a6002f931f733ea"},
	"1.2":            []string{"9bd58461553810e6b1d38b11ddb57a99724d2208d03a2794e8199412d858dcc1"},
	"2.0-m1":         []string{"7dd9376ec02b76d3da67ec98356a9c35f2f11c243075858d07008d800d7ea3ef"},
	"2.0-m2":         []string{"d833342086ee83e249d4142ae8389a0dbcda5b14b28d687e1b4e9a39c2460350"},
	"2.0-m3":         []string{"2eb874942c3522819cb847aaa28dbcc6473370fb34d632793e1d57cdcd0dd289"},
	"2.0-m4":         []string{"d3cd20e275c4b05381a918947f4aa3b91a764479039310a0dc5663ef3689b35c"},
	"2.0-rc1":        []string{"71f4a5a4b3dcc2492f91c4b17f4b20d3ebeb8fb6402bb28853e9658626a2a370"},
	"2.0-rc2":        []string{"5695271ad4f62a002feef4f85a486f963f5df613ab35f5d46c312abac49bd1b6"},
	"2.0.1":          []string{"d0a6db012ae7c491420e14749b57fca779aff62e1cc4689324aa712430df805b"},
	"2.0.2":          []string{"3a278529027cea3653911c71a944816799d85d785880bad3a714c7bb68807c55"},
	"2.0.4":          []string{"3d71e0e414594789d617ef0760a159f465db7f19fd2c11ed589bd9e13335c25d"},
	"2.0.5":          []string{"eeaaac30a472a055a9063a110b78c80080fc8ca35b425d8f07207cce45c6bb1c"},
	"2.0.6":          []string{"63544062fe7cf8166a422753f52dad709fbdfb2bf66ec0ee8b62e7d90fea7528"},
	"2.0.7":          []string{"4a7c4ca5f7b3a2e24c1022a78dc8a466a0191549ea806fa7e7a67d4e9318c7a0"},
	"2.0.8":          []string{"9cfbacf832b7e10676a54d9b5b72fa972ca8a644745b1079b9a1564155854f45"},
	"2.5.1":          []string{"479fd8e68cde3ce460660cda5d20a4701459500c19509be47a23c1c30112beef"},
	"2.5.2":          []string{"114c55bed5fc4847fb1fefe8462f65b0e89bc216a0d31f6325f021c6b2381312"},
	"2.5.3":          []string{"1d1e9df5d7d3ef29755889254a62b9e1784630052407f3ea51b60e676edeb3fb"},
	"2.5.5":          []string{"69a94e366da93af085ec346fa5c93442de0f919efd7b983e9e514af2fe6e143b"},
	"2.5.6.SEC01":    []string{"0b53260c6e85c6848a4ae181f790696acd9e784dbaf05f8cee9acdda8afff4c2"},
	"2.5.6.SEC02":    []string{"b6a7845ff9068b36a67d7c7bf41afbcd76413ff63e7bec2414133a18ef330b7a"},
	"2.5.6":          []string{"d33246bb33527685d04f23536ebf91b06ad7fa8b371fcbeb12f01523eb610104"},
	"2.5":            []string{"0add4113f10bd6681b39e969ad5b7bf3ed2b6ebdbd0ae07b64ee4af1b5f0b2a0"},
	"3.0.0.RELEASE":  []string{"4271b137c17b9367ad06267079a28ae4dfdd493d4c9d15c7437a48dcae38b28c"},
	"3.0.2.RELEASE":  []string{"e0b8fc0c39349b8a9b5ac4f0276109c39f2e6c6a2de74ab1c1530122d4a3e5a8"},
	"3.0.3.RELEASE":  []string{"ea514ebc81da83161ac163831500e58d4f7199d0cfe12d14eaa11b42953b5771"},
	"3.0.5.RELEASE":  []string{"ab6c3906ea07d6652633538c67014eb840b4fd57fba1fc6dc47152013dc50106"},
	"3.0.6.RELEASE":  []string{"2570f90c86ef7a5f09dc36f28f05a1c24179971acae84fa5f837dcc82cb0c33e"},
	"3.0.7.RELEASE":  []string{"a7ae604dd25f6caa1729a63bfa01b8bf4d05ca8a7169d46b6078fa921c667f6f"},
	"3.1.1.RELEASE":  []string{"3540ef743e77825c69971b6c3925df2a855dbdff4dae44db7fb642d51f9400c5"},
	"3.1.2.RELEASE":  []string{"685f0759b30c9413e689e906cf3e0717d6b01a044dc00b04be0b56c028c5b550"},
	"3.1.4.RELEASE":  []string{"df74f8eb302dd1ef078031c24bad4677ae2b2d6b0ef5a186c51168e6bcee50b5"},
	"3.2.0.RELEASE":  []string{"f73909a197c72fe98c19d924136c2699e9ba2d701e6d6a5a5e232e8be42d0e52"},
	"3.2.1.RELEASE":  []string{"b6563a290f5f8a40c549ea0b6dbd67a8fb41cd654fa8cc132452146f81214dc9"},
	"3.2.11.RELEASE": []string{"603de664d1f51f35cedc7995b4d4d9d76aa9e061d8e765428df4d5c3fb0c7dff"},
	"3.2.12.RELEASE": []string{"c79c3f5f5f62bfbc6a8637293dffd3c7af932755a2916393c232648492f01e2f"},
	"3.2.14.RELEASE": []string{"3b03774fe60911d4167d322cc7689be3df33c249f22d928aacecc78d27c8f073"},
	"3.2.15.RELEASE": []string{"9e0142f6dc0fe58c4a2df3d926fb4343787a4ce9d19f474c3b56e3acfc8997ab"},
	"3.2.17.RELEASE": []string{"265b257bc2db930fb814bc27dcacf3a30d1057436a88e2091c93ed2def304ea3"},
	"3.2.18.RELEASE": []string{"3ca7e8e3a2a053229fef927a315f038ee94a79368c396e50727eeedce9aef2c9"},
	"3.2.4.RELEASE":  []string{"387025a34350812978f39c5cd89484379702d617712f23f567f0dd61952aa573"},
	"3.2.5.RELEASE":  []string{"b31d4ee6144da90546363a52346b1c101e10c99af96a0393533afd5ed3f98f9d"},
	"3.2.7.RELEASE":  []string{"0533a84d689365699c468f0e6b84f5fd822ab0c4ce1e09c2d673313a087d9e3a"},
	"3.2.8.RELEASE":  []string{"caa6d6daaab7829abf87ac9b22a3dbec5d58549a4d489c19367155055f8dc010"},
	"3.2.9.RELEASE":  []string{"6366e84278e827bcb3cb68041bab7318727c83d7dad7a9e439162aec9e711980"},
	"4.0.1.RELEASE":  []string{"e27e14f2eff27a97563b0f7dec4a81ab1ffc0d088c29e68eea189f148bc591c8"},
	"4.0.2.RELEASE":  []string{"eeec5762999af8079c3363c9112344d830f70a605f720b5c68a1fd1350cc8d80"},
	"4.0.4.RELEASE":  []string{"bbe70bf71016a47418797ed40969a836a2090af8e56375dff7e209e00b4aea2d"},
	"4.0.5.RELEASE":  []string{"0b506df2e1f59e2c894e109762a6bfee55fbdfdb81d15f66b2c617d1d2c77e7d"},
	"4.0.7.RELEASE":  []string{"21103a81e9da152abfda773b8d9f0cf173729e531194772188ec15401e759eba"},
	"4.0.8.RELEASE":  []string{"89105ba2af53e415af3fe137ae251e747650e48118aae136d56632cf06b1e1ca"},
	"4.1.0.RELEASE":  []string{"56c99ed15ed2e4380fe04ffe951b02c6dadb08583889b47f0c2f5156eb1e7d16"},
	"4.1.1.RELEASE":  []string{"d85cce5c0b06a4ded99150676ea3e5a59a3dda0db5940b5d99b757b221c72acd"},
	"4.1.3.RELEASE":  []string{"94f160690e4d5f80a0444088aaf235086b448f3903043da06f24ff4b713fb713"},
	"4.1.5.RELEASE":  []string{"2224dfb1ae4c4630146998f9f9e44364a4ab99ba6ffcdbbf81c6aeb9c58bbab8"},
	"4.1.6.RELEASE":  []string{"b04ccc5aac8b2e712c33ca0b5e93b401dc4381e025cd94c60a87579bbcac1d5e"},
	"4.1.8.RELEASE":  []string{"a51bff1168f37e643118bd28180523f17976db8b4eafde542f63725418c0d0a4"},
	"4.1.9.RELEASE":  []string{"cb677671c5c74f787642324e1ed61afb00c50e7a62fb5c3dce93dbffe73645cb"},
	"4.2.1.RELEASE":  []string{"55442596df4e0778e0bb6c9094d703549e364dd48bbf71d1c5a354dd2d95b4a7"},
	"4.2.2.RELEASE":  []string{"7814419f421a58d66fc586851685e383919de381fdc8921ec9f4fb67dee563af"},
	"4.2.4.RELEASE":  []string{"d47cf4b4294966239600c8e044e557646fb139dae758f857494ee1c1ab1e2046"},
	"4.2.5.RELEASE":  []string{"8ad81e4b404684f6cc9501491d14761ac7d186106608a51f69d931426243ec10"},
	"4.2.7.RELEASE":  []string{"7d863ede27b894865b3dbfad128602a1853bd3e39b1c31a2d100f7cf1996a4ee"},
	"4.2.8.RELEASE":  []string{"5c83be1169fb272c217500eb44c03bff44a4e56f8a8debeb9ebfb68272215dd7"},
	"4.3.0.RELEASE":  []string{"b50e9413a4ae780b613fcecf65b6c0270f28e86876b0874dbca4e9f88af95f6e"},
	"4.3.1.RELEASE":  []string{"44d5dca971b2ab6454d125ab271c1f32dff035bc578792c8ed702f0c57ac5a2a"},
	"4.3.11.RELEASE": []string{"9f7d87ff3683ebc491bf34630fc9fb44228e51e69bb81131f7ebdfc96796337b"},
	"4.3.12.RELEASE": []string{"72287ccbfa246cbabb718414d74c2cf56d5fb0b3d8145a726a1f9b09acd25cd8"},
	"4.3.14.RELEASE": []string{"62ba63c30d30a221b69ce77d5d626554af1d61dc736cebd45ba7c688ee1048ab"},
	"4.3.16.RELEASE": []string{"8dc528e4e9998f626a6072a087d8d155a3c833515790dff01785b7efe86d7f5a"},
	"4.3.17.RELEASE": []string{"6ea0cae9ce926db7227d3e5d8e11e4f75663f6de08702868c320ea32a2c0c015"},
	"4.3.19.RELEASE": []string{"88785cd6d433df6d69224622f52cedfc29d1e7a38c61d7dac29c75965cb93fcd"},
	"4.3.2.RELEASE":  []string{"371db87afff450333044949529d0de193aa55e1c789ec4553cca18d3f4f39cf2"},
	"4.3.21.RELEASE": []string{"6b6f6bca063d4c29f487d9480b48f392b308c20fa2b14934375044f502e91361"},
	"4.3.22.RELEASE": []string{"c9a97296f07e8e96d3d3f63c9cb3700c4baf4c2ecf6463a1a1c920b463ee45b6"},
	"4.3.24.RELEASE": []string{"364926a54114ec84772310e486ce080655a85a45c704e54d44a7bfab9aaa873b"},
	"4.3.26.RELEASE": []string{"fd7d135ee5dfa3d72ba4f195ba42127b84968c3bc12fb1a2496512778f5b3c77"},
	"4.3.27.RELEASE": []string{"e52fe430ba9f19be62da1882fbd43222f8be4cf42860472ad81e991c832c1c5a"},
	"4.3.29.RELEASE": []string{"a1ac25edb27aa17ec3ddd4fc05982b6b12ce9d743fb2c1c630d9405da21a257f"},
	"4.3.3.RELEASE":  []string{"59c0c1f9c5079310334b4962798c5db9f5cfecf6c4278f8a3b454da727083a86"},
	"4.3.4.RELEASE":  []string{"3022a556842e191dcd4b33dcd04657890ff0fdcf40f9943aa8c3d809a9de8d6e"},
	"4.3.5.RELEASE":  []string{"da9e4ef3716d2fac235767107e12e906bfc8da10b4b61c0725daf277dcc20c8f"},
	"4.3.7.RELEASE":  []string{"515cb4b7987aea17e1c02e9b9f64f44ad44b645de4bd2417b88bfb7550068bb8"},
	"4.3.9.RELEASE":  []string{"6190599448d7ee68f4b4dd17fc6d963c9f721f34736cdc85273b56ce9fb9ee0d"},
	"5.0.0.RELEASE":  []string{"062cd8eb1ed897f05d742f0ae00f87c041ba1bd28f0ed260849e30aca352494f"},
	"5.0.10.RELEASE": []string{"2d88012690cbb45d0afaa33417a5c7e24fc9a42c16c65cb25ffe939430a47730"},
	"5.0.11.RELEASE": []string{"37122e1f376f412289e9f4bb3767a870592fdf47d555448425479453ee520e64"},
	"5.0.13.RELEASE": []string{"af2afab52ff8ad7777f6a239837fabc329fc88509b98b023f0c7e8bcbddd0ffd"},
	"5.0.14.RELEASE": []string{"840056ad4625308728883b4f2568bc8360ae2374c7bde761c07115306cd18c47"},
	"5.0.15.RELEASE": []string{"0e0b943cb1e76d11bd2575b2dd25f800f4faa50343933e3251e8fda745f30d6d"},
	"5.0.17.RELEASE": []string{"d671cebd74b33d2e47a4882b202ba39cf3604cebd6fb6fb422076c117763cba3"},
	"5.0.18.RELEASE": []string{"2e886923eba3d13c6fb7b7894b409190476c82312df27793d9a5ac6a70f85e7e"},
	"5.0.2.RELEASE":  []string{"11899e7e0aaca6fa63c3608e751964cd280395806df1e65c738f188cb52c4020"},
	"5.0.20.RELEASE": []string{"7d10d8df090f111c1e419a1a85d808e89fb95abd62e0e7d4da592c792238bed8"},
	"5.0.4.RELEASE":  []string{"cd559673273afb16f7580ab063f07e9821f644a7f471a41179e5fead45c7f708"},
	"5.0.5.RELEASE":  []string{"dab1f19aafd2d53137c886b806cdc2a4f2193e66f55b96a37d10fb92fd204663"},
	"5.0.7.RELEASE":  []string{"0d0adc1832406304985a72d2c79c6d0af481f34ae2a9c4a3835c9b0968da25e3"},
	"5.0.8.RELEASE":  []string{"b846720875814e9a383421af0c6a2026e563ec903b2e437926792fea493fe84d"},
	"5.1.0.RELEASE":  []string{"e2b00ade5ffbacbb30e529919f6132cc1fce1e5883fb33840ebae6b190eab64e"},
	"5.1.1.RELEASE":  []string{"57d7094cf81d5fb11acf68f8b103dd125159b4eab9c85438d61e56c237c8b759"},
	"5.1.10.RELEASE": []string{"c82469fd2715bdb3194dff9ab3fbb215f351473d428fc169328d975b30992b9d"},
	"5.1.12.RELEASE": []string{"2097e8357dc6f5e67e4a165155d68710ff0166906378fc2e4a41f0854d64d46f"},
	"5.1.13.RELEASE": []string{"f7552c59e527d596ceea7adba4ef47c9e4afd8e709dce259fcc5531e19814880"},
	"5.1.15.RELEASE": []string{"32ab12c5e0e43f75244030fb5245922df22d1f5aea89bff7ff533623b8e8a1f9"},
	"5.1.16.RELEASE": []string{"2bc36d22beb2749dbf630ca2641bafa30278f13d8f80968c98a0d1d3c4759702"},
	"5.1.18.RELEASE": []string{"9f28e099b9a744ee71bb0d6df5add0e4918952f05d74704675d237eff5ca0df0"},
	"5.1.19.RELEASE": []string{"f12582d4a80d9e3274780736d896de0e7e1827b30c4f9c25c3bfe49bacf257e2"},
	"5.1.20.RELEASE": []string{"0dee11372aff769035f8610421ecb18ab809ac66af424ae3b0ceedb6983989f7"},
	"5.1.3.RELEASE":  []string{"6702b1f7b7440512b9fe7d04f48762ac8b4be65fc2554079a1da4d6285c581f3"},
	"5.1.5.RELEASE":  []string{"7f759c26bfc4697346de39993df48b2dac49f502d5d4e5d69f19054edc4376f5"},
	"5.1.6.RELEASE":  []string{"230fc4bd94573bdd0fade9e492b218338a2260fc737b4ea853b877cc447be994"},
	"5.1.7.RELEASE":  []string{"10fa2771d73d6acf49df96bae9c64d569f6d34564d14d9498f6a52d11850942d"},
	"5.1.9.RELEASE":  []string{"e53ac6c352a41050c9f2186590157bbe61899428f3d62bab772f1ef96f141237"},
	"5.2.0.RELEASE":  []string{"7d8dab8ecc1b1575086603a204cf688ec8fd85ecaeeba00ba87cb1328c54c5ed"},
	"5.2.10.RELEASE": []string{"f26ed1a9b3de49467948a9b5ca4e7a973a064bc27430fd1b419f075683cc08be"},
	"5.2.11.RELEASE": []string{"152bcc4a387bde12ed73b6c0895fca44b79e5ac2a07a6f2e3959a33b8730528f"},
	"5.2.13.RELEASE": []string{"ec519a30fa342ff96f55a8641cc423907ffd193d759dda50c1b77997e11c6457"},
	"5.2.14.RELEASE": []string{"61b833a6cae1108ad45cd95ed87944d41b412f971a617fbf4f3287380d7b7967"},
	"5.2.16.RELEASE": []string{"2f93b539d3d71c07f3923386c78e9fad3f06361a84bc9ed7615d38c176824162"},
	"5.2.18.RELEASE": []string{"9df567b7d52175ba32d6b2bded4f64ef41080abbc7bcfaabed4f4cd343080dbe"},
	"5.2.19.RELEASE": []string{"2163508fae468a14035ae4afe476803a701078d76a73448224331754822e7626"},
	"5.2.2.RELEASE":  []string{"58f16fa6718d9e2a456036b681b68dc38802c0da6c90feaf1e63a160b3b74cac"},
	"5.2.4.RELEASE":  []string{"b90ec0db31c54cd72550337e239c18765afaf5d85c5a02fc0db42f0149babc53"},
	"5.2.5.RELEASE":  []string{"f22d8034a6795311e642974225058db0b8078864e62c420a431fb46d649a0f54"},
	"5.2.7.RELEASE":  []string{"a646527fce622e348c889f72338967d23831ac32e2b559506ed47e3a7041286b"},
	"5.2.8.RELEASE":  []string{"dc4e0f8014ca6c4ffe02e854e2f3fd548c384f208a69808f08d7ea56ab0849a0"},
	"5.3.0":          []string{"1c58981f2062466f171ee50e48ab9e6b6efe1829e3175633d77dac267c1b76e7"},
	"5.3.1":          []string{"86f7c1cdac78f5fe6e2547d8faef52e8c3528526563b542c4922479f5422c440"},
	"5.3.11":         []string{"98a551453f431dce5730ad45b7005d414e844c4d743e442b20f3114a3031d71e"},
	"5.3.12":         []string{"a88c010991f572723109ebd4d9c38974ddb78f4477f97cf48e9d364ec35f3432"},
	"5.3.14":         []string{"b354f54923139b8d86bc594452a6f53329da7b1e0c2a6402f9d9ca24837091ad"},
	"5.3.15":         []string{"f4facec88ada2e86be062f90b3f1d39fd6660de7ecc2dc45afc45fb31e9699b2"},
	"5.3.17":         []string{"23ba3216644c33f10716dc158d33080a5e3f7457e660ec72bdccb26e777f2c74"},
	"5.3.2":          []string{"2fc52811a5a8bb5684957ba67ab5642d39833be624f2507e2577707e737670b2"},
	"5.3.4":          []string{"9ac9237516f7d53dffa7eb6b03c5da67de418d03826aee9e226c1b1d67baf90a"},
	"5.3.5":          []string{"a5736e63f93f68f32d9785c3a4a74fd956b382d92a55cd123908141cf0d9b220"},
	"5.3.6":          []string{"33331abcdd8acccea43666782a5807127a0d43ffc6abf1c3252fbb27fc3367b2"},
	"5.3.8":          []string{"fbb626312a695294b537150034f7e9fc5563908e02903b8c617d06df60e00380"},

	"5.3.18":         []string{"e962d99bf7b3753cded86ce8ce6b4be5bed27d0b59feeb2a85948e29bba2807d"},
	"5.2.20.RELEASE": []string{"ab242fb119664df49c64c8af8cfb1932446bdc342d3a56453e34f40fa860f0f4"},
}

type CVE struct {
	ID          string
	Description string
	Reference   []string
	Score       float64
}

var CVE_2022_22965 = CVE{
	ID:          "CVE-2022-22965",
	Description: `Spring Framework RCE via Data Binding on JDK 9+`,
	Reference: []string{
		"https://tanzu.vmware.com/security/cve-2022-22965",
	},
	Score: 9.8,
}

var CVE_2022_22963 = CVE{
	ID:          "CVE-2022-22963",
	Description: `Remote code execution in Spring Cloud Function by malicious Spring Expression`,
	Reference: []string{
		"https://tanzu.vmware.com/security/cve-2022-22963",
	},
	Score: 9.8,
}

var vulnerabilities = map[string][]CVE{
	"1.2-rc1":        []CVE{CVE_2022_22965},
	"1.2-rc2":        []CVE{CVE_2022_22965},
	"1.2.1":          []CVE{CVE_2022_22965},
	"1.2.2":          []CVE{CVE_2022_22965},
	"1.2.3":          []CVE{CVE_2022_22965},
	"1.2.4":          []CVE{CVE_2022_22965},
	"1.2.5":          []CVE{CVE_2022_22965},
	"1.2.6":          []CVE{CVE_2022_22965},
	"1.2.8":          []CVE{CVE_2022_22965},
	"1.2.9":          []CVE{CVE_2022_22965},
	"1.2":            []CVE{CVE_2022_22965},
	"2.0-m1":         []CVE{CVE_2022_22965},
	"2.0-m2":         []CVE{CVE_2022_22965},
	"2.0-m3":         []CVE{CVE_2022_22965},
	"2.0-m4":         []CVE{CVE_2022_22965},
	"2.0-rc1":        []CVE{CVE_2022_22965},
	"2.0-rc2":        []CVE{CVE_2022_22965},
	"2.0.1":          []CVE{CVE_2022_22965},
	"2.0.2":          []CVE{CVE_2022_22965},
	"2.0.4":          []CVE{CVE_2022_22965},
	"2.0.5":          []CVE{CVE_2022_22965},
	"2.0.6":          []CVE{CVE_2022_22965},
	"2.0.7":          []CVE{CVE_2022_22965},
	"2.0.8":          []CVE{CVE_2022_22965},
	"2.5.1":          []CVE{CVE_2022_22965},
	"2.5.2":          []CVE{CVE_2022_22965},
	"2.5.3":          []CVE{CVE_2022_22965},
	"2.5.5":          []CVE{CVE_2022_22965},
	"2.5.6.SEC01":    []CVE{CVE_2022_22965},
	"2.5.6.SEC02":    []CVE{CVE_2022_22965},
	"2.5.6":          []CVE{CVE_2022_22965},
	"2.5":            []CVE{CVE_2022_22965},
	"3.0.0.RELEASE":  []CVE{CVE_2022_22965},
	"3.0.2.RELEASE":  []CVE{CVE_2022_22965},
	"3.0.3.RELEASE":  []CVE{CVE_2022_22965},
	"3.0.5.RELEASE":  []CVE{CVE_2022_22965},
	"3.0.6.RELEASE":  []CVE{CVE_2022_22965},
	"3.0.7.RELEASE":  []CVE{CVE_2022_22965},
	"3.1.1.RELEASE":  []CVE{CVE_2022_22965},
	"3.1.2.RELEASE":  []CVE{CVE_2022_22965},
	"3.1.4.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.0.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.1.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.11.RELEASE": []CVE{CVE_2022_22965},
	"3.2.12.RELEASE": []CVE{CVE_2022_22965},
	"3.2.14.RELEASE": []CVE{CVE_2022_22965},
	"3.2.15.RELEASE": []CVE{CVE_2022_22965},
	"3.2.17.RELEASE": []CVE{CVE_2022_22965},
	"3.2.18.RELEASE": []CVE{CVE_2022_22965},
	"3.2.4.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.5.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.7.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.8.RELEASE":  []CVE{CVE_2022_22965},
	"3.2.9.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.1.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.2.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.4.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.5.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.7.RELEASE":  []CVE{CVE_2022_22965},
	"4.0.8.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.0.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.1.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.3.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.5.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.6.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.8.RELEASE":  []CVE{CVE_2022_22965},
	"4.1.9.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.1.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.2.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.4.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.5.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.7.RELEASE":  []CVE{CVE_2022_22965},
	"4.2.8.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.0.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.1.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.11.RELEASE": []CVE{CVE_2022_22965},
	"4.3.12.RELEASE": []CVE{CVE_2022_22965},
	"4.3.14.RELEASE": []CVE{CVE_2022_22965},
	"4.3.16.RELEASE": []CVE{CVE_2022_22965},
	"4.3.17.RELEASE": []CVE{CVE_2022_22965},
	"4.3.19.RELEASE": []CVE{CVE_2022_22965},
	"4.3.2.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.21.RELEASE": []CVE{CVE_2022_22965},
	"4.3.22.RELEASE": []CVE{CVE_2022_22965},
	"4.3.24.RELEASE": []CVE{CVE_2022_22965},
	"4.3.26.RELEASE": []CVE{CVE_2022_22965},
	"4.3.27.RELEASE": []CVE{CVE_2022_22965},
	"4.3.29.RELEASE": []CVE{CVE_2022_22965},
	"4.3.3.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.4.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.5.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.7.RELEASE":  []CVE{CVE_2022_22965},
	"4.3.9.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.0.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.10.RELEASE": []CVE{CVE_2022_22965},
	"5.0.11.RELEASE": []CVE{CVE_2022_22965},
	"5.0.13.RELEASE": []CVE{CVE_2022_22965},
	"5.0.14.RELEASE": []CVE{CVE_2022_22965},
	"5.0.15.RELEASE": []CVE{CVE_2022_22965},
	"5.0.17.RELEASE": []CVE{CVE_2022_22965},
	"5.0.18.RELEASE": []CVE{CVE_2022_22965},
	"5.0.2.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.20.RELEASE": []CVE{CVE_2022_22965},
	"5.0.4.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.5.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.7.RELEASE":  []CVE{CVE_2022_22965},
	"5.0.8.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.0.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.1.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.10.RELEASE": []CVE{CVE_2022_22965},
	"5.1.12.RELEASE": []CVE{CVE_2022_22965},
	"5.1.13.RELEASE": []CVE{CVE_2022_22965},
	"5.1.15.RELEASE": []CVE{CVE_2022_22965},
	"5.1.16.RELEASE": []CVE{CVE_2022_22965},
	"5.1.18.RELEASE": []CVE{CVE_2022_22965},
	"5.1.19.RELEASE": []CVE{CVE_2022_22965},
	"5.1.20.RELEASE": []CVE{CVE_2022_22965},
	"5.1.3.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.5.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.6.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.7.RELEASE":  []CVE{CVE_2022_22965},
	"5.1.9.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.0.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.10.RELEASE": []CVE{CVE_2022_22965},
	"5.2.11.RELEASE": []CVE{CVE_2022_22965},
	"5.2.13.RELEASE": []CVE{CVE_2022_22965},
	"5.2.14.RELEASE": []CVE{CVE_2022_22965},
	"5.2.16.RELEASE": []CVE{CVE_2022_22965},
	"5.2.18.RELEASE": []CVE{CVE_2022_22965},
	"5.2.19.RELEASE": []CVE{CVE_2022_22965},
	"5.2.2.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.4.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.5.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.7.RELEASE":  []CVE{CVE_2022_22965},
	"5.2.8.RELEASE":  []CVE{CVE_2022_22965},
	"5.3.0":          []CVE{CVE_2022_22965},
	"5.3.1":          []CVE{CVE_2022_22965},
	"5.3.11":         []CVE{CVE_2022_22965},
	"5.3.12":         []CVE{CVE_2022_22965},
	"5.3.14":         []CVE{CVE_2022_22965},
	"5.3.15":         []CVE{CVE_2022_22965},
	"5.3.17":         []CVE{CVE_2022_22965},
	"5.3.2":          []CVE{CVE_2022_22965},
	"5.3.4":          []CVE{CVE_2022_22965},
	"5.3.5":          []CVE{CVE_2022_22965},
	"5.3.6":          []CVE{CVE_2022_22965},
	"5.3.8":          []CVE{CVE_2022_22965},
	"5.2.20":         []CVE{},
	"5.3.18":         []CVE{},
}

var fileSignatures = []struct {
	Filename string
	Hash     string
	Version  string
}{
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2-rc1"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2-rc2"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2.1"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2.2"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2.3"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2.4"},
	{"CachedIntrospectionResults.class", "b932d7f04848f239dd143b67b70fd7fbe5b534dad03bbbd3b7395b07e7e9410c", "1.2.5"},
	{"CachedIntrospectionResults.class", "b932d7f04848f239dd143b67b70fd7fbe5b534dad03bbbd3b7395b07e7e9410c", "1.2.6"},
	{"CachedIntrospectionResults.class", "f18c9203afbcb1fadb40794b5a7ea80c4835bfb53684c55bb53603ec44d22c67", "1.2.8"},
	{"CachedIntrospectionResults.class", "4c52465f65d789ddfdf069dc4b96361810d55ee5c34a594769ded57fe1149aad", "1.2.9"},
	{"CachedIntrospectionResults.class", "448c235266cf50f3f0dda1943f162f655ddf085d866d7f166d526c4dcadc8a29", "1.2"},
	{"CachedIntrospectionResults.class", "be3a9e2f7fbb77f40eda831518d47877cc2cee84040ee9fd0d36832219f29499", "2.0-m1"},
	{"CachedIntrospectionResults.class", "be3a9e2f7fbb77f40eda831518d47877cc2cee84040ee9fd0d36832219f29499", "2.0-m2"},
	{"CachedIntrospectionResults.class", "be3a9e2f7fbb77f40eda831518d47877cc2cee84040ee9fd0d36832219f29499", "2.0-m3"},
	{"CachedIntrospectionResults.class", "be3a9e2f7fbb77f40eda831518d47877cc2cee84040ee9fd0d36832219f29499", "2.0-m4"},
	{"CachedIntrospectionResults.class", "cb0d9931738a169aa4c117f6b57ff6ac83d204ddbda3f31268008050476fe1a5", "2.0-rc1"},
	{"CachedIntrospectionResults.class", "cb0d9931738a169aa4c117f6b57ff6ac83d204ddbda3f31268008050476fe1a5", "2.0-rc2"},
	{"CachedIntrospectionResults.class", "3d2211c75c08fb0cac07d238dc5713d0ac4529693dec8bf97ac0add4a18466ff", "2.0.1"},
	{"CachedIntrospectionResults.class", "cfd1c5e1376ec430447caefbc40e9ab26096a8826f8bf6807aeebf343f860a1c", "2.0.2"},
	{"CachedIntrospectionResults.class", "6c703b424fe894c0fa6261c6d8a4f9d18d5107e292cf7599489619239f114068", "2.0.4"},
	{"CachedIntrospectionResults.class", "6c703b424fe894c0fa6261c6d8a4f9d18d5107e292cf7599489619239f114068", "2.0.5"},
	{"CachedIntrospectionResults.class", "6c703b424fe894c0fa6261c6d8a4f9d18d5107e292cf7599489619239f114068", "2.0.6"},
	{"CachedIntrospectionResults.class", "6c703b424fe894c0fa6261c6d8a4f9d18d5107e292cf7599489619239f114068", "2.0.7"},
	{"CachedIntrospectionResults.class", "6c703b424fe894c0fa6261c6d8a4f9d18d5107e292cf7599489619239f114068", "2.0.8"},
	{"CachedIntrospectionResults.class", "ac4060593a2576c613fe458880a524e003177abb9cc973026e95f291d2166520", "2.5.1"},
	{"CachedIntrospectionResults.class", "640bfd278bea06b2dc720ab42fc49bbabd42e5982115a7edd932bbd358823a2e", "2.5.2"},
	{"CachedIntrospectionResults.class", "9112d87b4ccd789783f381738f90c166d3a6383b199bb222b966fd255ae7340c", "2.5.3"},
	{"CachedIntrospectionResults.class", "9112d87b4ccd789783f381738f90c166d3a6383b199bb222b966fd255ae7340c", "2.5.5"},
	{"CachedIntrospectionResults.class", "9112d87b4ccd789783f381738f90c166d3a6383b199bb222b966fd255ae7340c", "2.5.6.SEC01"},
	{"CachedIntrospectionResults.class", "1a171691ba1e8dac7134ac4e81744e4c170235e6fba23bd8082ced06021f48b5", "2.5.6.SEC02"},
	{"CachedIntrospectionResults.class", "9112d87b4ccd789783f381738f90c166d3a6383b199bb222b966fd255ae7340c", "2.5.6"},
	{"CachedIntrospectionResults.class", "ac4060593a2576c613fe458880a524e003177abb9cc973026e95f291d2166520", "2.5"},
	{"CachedIntrospectionResults.class", "f1abaf4f24c5f10ae85266b30fda5568c09da74289866e271e861b33f2cf6233", "3.0.0.RELEASE"},
	{"CachedIntrospectionResults.class", "f1abaf4f24c5f10ae85266b30fda5568c09da74289866e271e861b33f2cf6233", "3.0.2.RELEASE"},
	{"CachedIntrospectionResults.class", "c22483f1556f5a5c7ae6d565de6ab3c19633e9d8328b7ac95cadc832dd797269", "3.0.3.RELEASE"},
	{"CachedIntrospectionResults.class", "c22483f1556f5a5c7ae6d565de6ab3c19633e9d8328b7ac95cadc832dd797269", "3.0.5.RELEASE"},
	{"CachedIntrospectionResults.class", "c22483f1556f5a5c7ae6d565de6ab3c19633e9d8328b7ac95cadc832dd797269", "3.0.6.RELEASE"},
	{"CachedIntrospectionResults.class", "c22483f1556f5a5c7ae6d565de6ab3c19633e9d8328b7ac95cadc832dd797269", "3.0.7.RELEASE"},
	{"CachedIntrospectionResults.class", "912b1b2d9adf4d6e4894fbb00d840580297980917a7714d56490977fd68ee485", "3.1.1.RELEASE"},
	{"CachedIntrospectionResults.class", "912b1b2d9adf4d6e4894fbb00d840580297980917a7714d56490977fd68ee485", "3.1.2.RELEASE"},
	{"CachedIntrospectionResults.class", "8d23c596562a63732c4af68a3e65e7bfd69af2496cb9d28b87d8b8f46168320d", "3.1.4.RELEASE"},
	{"CachedIntrospectionResults.class", "b4c534e0dbdb7cbb47ea9ab19b89048de3a3fe25abf837951361f05ff56f4051", "3.2.0.RELEASE"},
	{"CachedIntrospectionResults.class", "4583a7ff7649ceded0ccdf1a8af055145fb4d49746365d2c2d1d96742b68a324", "3.2.1.RELEASE"},
	{"CachedIntrospectionResults.class", "8da7b0c7ce1edd13c42390038b172bccb60f19946973d5862f6f40e2e30df3b2", "3.2.11.RELEASE"},
	{"CachedIntrospectionResults.class", "8da7b0c7ce1edd13c42390038b172bccb60f19946973d5862f6f40e2e30df3b2", "3.2.12.RELEASE"},
	{"CachedIntrospectionResults.class", "8da7b0c7ce1edd13c42390038b172bccb60f19946973d5862f6f40e2e30df3b2", "3.2.14.RELEASE"},
	{"CachedIntrospectionResults.class", "8da7b0c7ce1edd13c42390038b172bccb60f19946973d5862f6f40e2e30df3b2", "3.2.15.RELEASE"},
	{"CachedIntrospectionResults.class", "8da7b0c7ce1edd13c42390038b172bccb60f19946973d5862f6f40e2e30df3b2", "3.2.17.RELEASE"},
	{"CachedIntrospectionResults.class", "7ca6f357f34ac6f9472d86ea078935041ea45318c5cb371a526c9e115255c3b3", "3.2.18.RELEASE"},
	{"CachedIntrospectionResults.class", "4583a7ff7649ceded0ccdf1a8af055145fb4d49746365d2c2d1d96742b68a324", "3.2.4.RELEASE"},
	{"CachedIntrospectionResults.class", "18af335c5c28d244824cb31216d7ba6f8d178ba608a5f694a3da85bd3b89c58f", "3.2.5.RELEASE"},
	{"CachedIntrospectionResults.class", "67a145a8a9205d77fc9d185aea0cddc946822357e7df645f305c0d60b723af4a", "3.2.7.RELEASE"},
	{"CachedIntrospectionResults.class", "3559f9cda734a0516efb5a72fa6cea004ae50e96f0bf20f8dc1b7d90741f2ca1", "3.2.8.RELEASE"},
	{"CachedIntrospectionResults.class", "3559f9cda734a0516efb5a72fa6cea004ae50e96f0bf20f8dc1b7d90741f2ca1", "3.2.9.RELEASE"},
	{"CachedIntrospectionResults.class", "0591c411a21147008fb83cc5e241ed921b271438dac99479da5c0ca3bb1b40f2", "4.0.1.RELEASE"},
	{"CachedIntrospectionResults.class", "e25682d908e833998ea36ad169a1042241fd228437ebc4e696c97f9972ffccef", "4.0.2.RELEASE"},
	{"CachedIntrospectionResults.class", "e25682d908e833998ea36ad169a1042241fd228437ebc4e696c97f9972ffccef", "4.0.4.RELEASE"},
	{"CachedIntrospectionResults.class", "e25682d908e833998ea36ad169a1042241fd228437ebc4e696c97f9972ffccef", "4.0.5.RELEASE"},
	{"CachedIntrospectionResults.class", "cdb9558412a80c0d6c320b5a7d42eb1153fa32243277e688a2bab34e9b7191e9", "4.0.7.RELEASE"},
	{"CachedIntrospectionResults.class", "cdb9558412a80c0d6c320b5a7d42eb1153fa32243277e688a2bab34e9b7191e9", "4.0.8.RELEASE"},
	{"CachedIntrospectionResults.class", "7214730c8f62485edf9c550e2cd60062aaea92efc20963993df9551ad3d76fd5", "4.1.0.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.1.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.3.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.5.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.6.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.8.RELEASE"},
	{"CachedIntrospectionResults.class", "c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989", "4.1.9.RELEASE"},
	{"CachedIntrospectionResults.class", "1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf", "4.2.1.RELEASE"},
	{"CachedIntrospectionResults.class", "1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf", "4.2.2.RELEASE"},
	{"CachedIntrospectionResults.class", "1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf", "4.2.4.RELEASE"},
	{"CachedIntrospectionResults.class", "1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf", "4.2.5.RELEASE"},
	{"CachedIntrospectionResults.class", "1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf", "4.2.7.RELEASE"},
	{"CachedIntrospectionResults.class", "0f2f9a511f22bacaf8df52a4fa7c80b04072043b69205945c61ef98722188d99", "4.2.8.RELEASE"},
	{"CachedIntrospectionResults.class", "03c8db6bb825f217ebf7a2718e78ac2edf2962db28b4a610a36366a916d13c15", "4.3.0.RELEASE"},
	{"CachedIntrospectionResults.class", "03c8db6bb825f217ebf7a2718e78ac2edf2962db28b4a610a36366a916d13c15", "4.3.1.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.11.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.12.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.14.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.16.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.17.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.19.RELEASE"},
	{"CachedIntrospectionResults.class", "03c8db6bb825f217ebf7a2718e78ac2edf2962db28b4a610a36366a916d13c15", "4.3.2.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.21.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.22.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.24.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.26.RELEASE"},
	{"CachedIntrospectionResults.class", "1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24", "4.3.27.RELEASE"},
	{"CachedIntrospectionResults.class", "4a91519d64e3ad5ecab3e1cefbc2e175c5941e8230d8ce54de7b887338d02d84", "4.3.29.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.3.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.4.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.5.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.7.RELEASE"},
	{"CachedIntrospectionResults.class", "68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c", "4.3.9.RELEASE"},
	{"CachedIntrospectionResults.class", "38a47d4367cd76b957de813b8066f5ee19b8a450b4b38acdaca713cf43db4080", "5.0.0.RELEASE"},
	{"CachedIntrospectionResults.class", "417fd370ca02fbe0a86c28d2bbe768c104a02e6fd50de31770c2df4f790e59ea", "5.0.10.RELEASE"},
	{"CachedIntrospectionResults.class", "417fd370ca02fbe0a86c28d2bbe768c104a02e6fd50de31770c2df4f790e59ea", "5.0.11.RELEASE"},
	{"CachedIntrospectionResults.class", "df8081e77e4f85cca548dc9265e6b080da3ff075c2a52e2e7acf0de329d9e948", "5.0.13.RELEASE"},
	{"CachedIntrospectionResults.class", "df8081e77e4f85cca548dc9265e6b080da3ff075c2a52e2e7acf0de329d9e948", "5.0.14.RELEASE"},
	{"CachedIntrospectionResults.class", "df8081e77e4f85cca548dc9265e6b080da3ff075c2a52e2e7acf0de329d9e948", "5.0.15.RELEASE"},
	{"CachedIntrospectionResults.class", "df8081e77e4f85cca548dc9265e6b080da3ff075c2a52e2e7acf0de329d9e948", "5.0.17.RELEASE"},
	{"CachedIntrospectionResults.class", "f4648837b518f82795216e23726f69e24536f1a8aaff335a810747ce25303136", "5.0.18.RELEASE"},
	{"CachedIntrospectionResults.class", "38a47d4367cd76b957de813b8066f5ee19b8a450b4b38acdaca713cf43db4080", "5.0.2.RELEASE"},
	{"CachedIntrospectionResults.class", "f4648837b518f82795216e23726f69e24536f1a8aaff335a810747ce25303136", "5.0.20.RELEASE"},
	{"CachedIntrospectionResults.class", "20ad82e25bab117d4c804e0648164841067781cc41e7b9e6f485e4d11073a485", "5.0.4.RELEASE"},
	{"CachedIntrospectionResults.class", "0726931727f081adc18f4cc8a9e12d1bc1bd8d489887bb6de1c1818d59086da3", "5.0.5.RELEASE"},
	{"CachedIntrospectionResults.class", "0726931727f081adc18f4cc8a9e12d1bc1bd8d489887bb6de1c1818d59086da3", "5.0.7.RELEASE"},
	{"CachedIntrospectionResults.class", "417fd370ca02fbe0a86c28d2bbe768c104a02e6fd50de31770c2df4f790e59ea", "5.0.8.RELEASE"},
	{"CachedIntrospectionResults.class", "c16dab0423510596a45160f09315bb432d655fd9abd35b88e9f9de833f6dda13", "5.1.0.RELEASE"},
	{"CachedIntrospectionResults.class", "c16dab0423510596a45160f09315bb432d655fd9abd35b88e9f9de833f6dda13", "5.1.1.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.1.10.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.1.12.RELEASE"},
	{"CachedIntrospectionResults.class", "82940fd349b672b2a341f2b283144eb6000b98b46603987078036a1e14f8c3dd", "5.1.13.RELEASE"},
	{"CachedIntrospectionResults.class", "82940fd349b672b2a341f2b283144eb6000b98b46603987078036a1e14f8c3dd", "5.1.15.RELEASE"},
	{"CachedIntrospectionResults.class", "85592077b7e9066793b345cb203252a6934e16da49c9c2b2aa83c4b7fbcfb91c", "5.1.16.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.1.18.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.1.19.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.1.20.RELEASE"},
	{"CachedIntrospectionResults.class", "c16dab0423510596a45160f09315bb432d655fd9abd35b88e9f9de833f6dda13", "5.1.3.RELEASE"},
	{"CachedIntrospectionResults.class", "c16dab0423510596a45160f09315bb432d655fd9abd35b88e9f9de833f6dda13", "5.1.5.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.1.6.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.1.7.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.1.9.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.2.0.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.10.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.11.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.13.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.14.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.16.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.18.RELEASE"},
	{"CachedIntrospectionResults.class", "54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a", "5.2.19.RELEASE"},
	{"CachedIntrospectionResults.class", "005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b", "5.2.2.RELEASE"},
	{"CachedIntrospectionResults.class", "82940fd349b672b2a341f2b283144eb6000b98b46603987078036a1e14f8c3dd", "5.2.4.RELEASE"},
	{"CachedIntrospectionResults.class", "82940fd349b672b2a341f2b283144eb6000b98b46603987078036a1e14f8c3dd", "5.2.5.RELEASE"},
	{"CachedIntrospectionResults.class", "85592077b7e9066793b345cb203252a6934e16da49c9c2b2aa83c4b7fbcfb91c", "5.2.7.RELEASE"},
	{"CachedIntrospectionResults.class", "85592077b7e9066793b345cb203252a6934e16da49c9c2b2aa83c4b7fbcfb91c", "5.2.8.RELEASE"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.0"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.1"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.11"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.12"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.14"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.15"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.17"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.2"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.4"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.5"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.6"},
	{"CachedIntrospectionResults.class", "f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922", "5.3.8"},

	{"CachedIntrospectionResults.class", "df420f4867849871af01edaf003e95377661ddd9012da38ffeed9fa32260e288", "5.2.20.RELEASE"},
	{"CachedIntrospectionResults.class", "1e40398b6fd070af5b6a75cc6329c1f3c897745b7a1b5f686e893066d0b7c61b", "5.3.18"},
}

func findFileHashes(hash []byte) []string {
	versions := []string{}

	for _, fh := range fileSignatures {
		dh, err := hex.DecodeString(fh.Hash)
		if err != nil {
			panic(err)
		}

		if bytes.Compare(hash, dh) != 0 {
			continue
		}

		versions = append(versions, fh.Version)
	}

	return versions
}

type unbufferedReaderAt struct {
	R io.ReadSeekCloser

	N int64
}

func NewUnbufferedReaderAt(r io.ReadSeekCloser) io.ReaderAt {
	return &unbufferedReaderAt{R: r}
}

func (u *unbufferedReaderAt) ReadAt(p []byte, off int64) (n int, err error) {

	if _, err := u.R.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}

	return u.R.Read(p)
}

func (b *fuzzer) IsAllowList(h []byte) bool {
	for _, v := range b.allowList {
		if bytes.Compare(v, h) == 0 {
			return true

		}
	}

	return false
}

type ArchiveFile interface {
	FileInfo() os.FileInfo
	Name() string
	Open() (io.ReadSeekCloser, error)
}

type ArchiveReader interface {
	Walk() <-chan interface{} // ArchiveFile or ArchiveError
}

type TARArchiveReader struct {
	*tar.Reader
}

type TARArchiveFile struct {
	*tar.Header

	r io.ReadSeeker
}

func (za *TARArchiveFile) Name() string {
	return za.Header.Name
}

type TARArchiveFileReader struct {
	io.ReadSeekCloser
}

// NopCloser returns a ReadCloser with a no-op Close method wrapping
// the provided Reader r.
func NopSeekCloser(r io.ReadSeeker) io.ReadSeekCloser {
	return nopSeekCloser{r}
}

type nopSeekCloser struct {
	io.ReadSeeker
}

func (nopSeekCloser) Close() error { return nil }

func (za *TARArchiveFile) Open() (io.ReadSeekCloser, error) {
	return &TARArchiveFileReader{NopSeekCloser(za.r)}, nil
}

func (za *TARArchiveFileReader) Close() error {
	io.Copy(io.Discard, za.ReadSeekCloser)
	return nil
}

func (za *TARArchiveReader) Walk() <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		for {
			header, err := za.Reader.Next()

			if err == io.EOF {
				break
			}

			if errors.Is(err, tar.ErrHeader) {
				// not a tar
				break
			}

			if errors.Is(err, io.ErrUnexpectedEOF) {
				// not a valid tar
				break
			}

			if err != nil {
				ch <- ArchiveError{p: "", Err: err}
				break
			}

			if header.Typeflag != tar.TypeReg {
				continue
			}

			size := header.Size

			if size > 1073741824 {
				// bailing out when file in tar is too large
				ch <- ArchiveError{p: header.Name, Err: fmt.Errorf("Could not scan file, file too large: %d bytes.", header.Size)}
				break
			}

			lr := io.LimitReader(za.Reader, header.Size)

			buff := bytes.NewBuffer([]byte{})

			if _, err := io.Copy(buff, lr); err != nil {
				ch <- ArchiveError{p: "", Err: err}
				continue
			}

			ch <- &TARArchiveFile{header, bytes.NewReader(buff.Bytes())}
		}
	}()

	return ch
}

func NewGzipTARArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	gr, err := gzip.NewReader(io.NewSectionReader(br, 0, size))
	if err != nil {
		return nil, err
	}

	r2 := tar.NewReader(gr)

	return &TARArchiveReader{r2}, nil
}

func NewTARArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	r2 := tar.NewReader(io.NewSectionReader(br, 0, size))

	return &TARArchiveReader{r2}, nil
}

type DirectoryReader struct {
	p           string
	excludeList []string
}

type DirectoryFile struct {
	fi os.FileInfo
	p  string
}

func (za *DirectoryFile) Name() string {
	return za.p
}
func (za *DirectoryFile) FileInfo() os.FileInfo {
	return za.fi
}

func (za *DirectoryFile) Open() (io.ReadSeekCloser, error) {
	r, err := os.OpenFile(za.p, os.O_RDONLY, 0)
	return r, err
}

type ArchiveError struct {
	p string

	Err error
}

func (ae *ArchiveError) Error() string {
	return ae.Err.Error()
}

func (za *DirectoryReader) Walk() <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		err := filepath.Walk(za.p, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				ch <- ArchiveError{p: za.p, Err: err}
				return nil
			}

			if info.IsDir() {
				if abs, _ := filepath.Abs(path); abs == "/proc" {
					return filepath.SkipDir
				} else if abs, _ := filepath.Abs(path); abs == "/dev" {
					return filepath.SkipDir
				} else if abs, _ := filepath.Abs(path); abs == "/net" {
					return filepath.SkipDir
				} else if abs, _ := filepath.Abs(path); abs == "/sys" {
					return filepath.SkipDir
				} else if IsExcluded(path, za.excludeList) {
					// only exclude real fs files
					return filepath.SkipDir
				}
			}

			if IsExcluded(path, za.excludeList) {
				return nil
			}

			if !info.Mode().IsRegular() {
				return nil
			}

			ch <- &DirectoryFile{fi: info, p: path}
			return nil
		})

		if err != nil {
			ch <- ArchiveError{p: za.p, Err: err}
			return
		}
	}()

	return ch
}

func NewDirectoryReader(p string, excludeList []string) (ArchiveReader, error) {
	return &DirectoryReader{p, excludeList}, nil
}

type ZIPArchiveFile struct {
	*zip.File
}

func (za *ZIPArchiveFile) Name() string {
	return za.File.Name
}

func (za *ZIPArchiveFile) Open() (io.ReadSeekCloser, error) {
	r, err := za.File.Open()
	if err != nil {
		return nil, err
	}

	buff := bytes.NewBuffer([]byte{})

	if _, err := io.Copy(buff, r); err != nil {
		return nil, err
	}

	return NopSeekCloser(bytes.NewReader(buff.Bytes())), nil
}

type ZIPArchiveReader struct {
	*zip.Reader
}

func (za *ZIPArchiveReader) Walk() <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		defer close(ch)
		for _, f := range za.Reader.File {
			if f.FileHeader.Flags&0x1 == 1 {
				ch <- ArchiveError{
					p:   f.Name,
					Err: fmt.Errorf("Could not open encrypted file in zip: %s", f.Name),
				}

				continue
			}

			ch <- &ZIPArchiveFile{f}
		}
	}()

	return ch
}

func NewZipArchiveReader(br io.ReaderAt, size int64) (ArchiveReader, error) {
	r2, err := zip.NewReader(br, size)
	if err != nil {
		return nil, err
	}

	return &ZIPArchiveReader{r2}, nil
}

type Stats struct {
	files               uint64
	images              uint64
	patched             uint64
	errors              uint64
	vulnerableLibraries uint64
	vulnerableFiles     uint64
}

func (s *Stats) Patched() uint64 {
	return atomic.LoadUint64(&s.patched)
}

func (s *Stats) Images() uint64 {
	return atomic.LoadUint64(&s.images)
}

func (s *Stats) IncImage() {
	atomic.AddUint64(&s.images, 1)
}

func (s *Stats) Files() uint64 {
	return atomic.LoadUint64(&s.files)
}

func (s *Stats) IncPatched() {
	atomic.AddUint64(&s.patched, 1)
}

func (s *Stats) IncFile() {
	atomic.AddUint64(&s.files, 1)
}

func (s *Stats) Errors() uint64 {
	return atomic.LoadUint64(&s.errors)
}

func (s *Stats) IncError() {
	atomic.AddUint64(&s.errors, 1)
}

func (s *Stats) VulnerableFiles() uint64 {
	return atomic.LoadUint64(&s.vulnerableFiles)
}

func (s *Stats) IncVulnerableFile() {
	atomic.AddUint64(&s.vulnerableFiles, 1)
}

func (s *Stats) VulnerableLibraries() uint64 {
	return atomic.LoadUint64(&s.vulnerableLibraries)
}

func (s *Stats) IncVulnerableLibrary() {
	atomic.AddUint64(&s.vulnerableLibraries, 1)
}

type ArchiveWriter interface {
	Create(fh interface{}) (io.WriteCloser, error)
	Close() error
}

type DirectoryWriter struct {
}

func (za *DirectoryWriter) Create(fh interface{}) (io.WriteCloser, error) {
	panic("this code isn't being used")
}

func (za *DirectoryWriter) Close() error {
	return nil
}

func NewDirectoryWriter(p string) (ArchiveWriter, error) {
	return &DirectoryWriter{}, nil
}

type ZIPArchiveWriter struct {
	*zip.Writer
}

type ZIPArchiveWriteCloser struct {
	io.Writer
}

func (wc *ZIPArchiveWriteCloser) Close() error {
	return nil
}

type TARArchiveWriter struct {
	*tar.Writer
}

func (za *TARArchiveWriter) Create(fh interface{}) (io.WriteCloser, error) {
	// should we use openraw
	tfh, ok := fh.(tar.Header)
	if !ok {
		return nil, fmt.Errorf("Expected tar fileheader")
	}

	if err := za.Writer.WriteHeader(&tfh); err != nil {
		return nil, err
	}

	return &TARArchiveWriteCloser{za.Writer}, nil
}

type TARArchiveWriteCloser struct {
	io.Writer
}

func (wc *TARArchiveWriteCloser) Close() error {
	return nil
}

func (za *ZIPArchiveWriter) Create(fh interface{}) (io.WriteCloser, error) {
	// should we use openraw

	zfh, ok := fh.(zip.FileHeader)
	if !ok {
		return nil, fmt.Errorf("Expected zip fileheader")
	}

	w, err := za.Writer.CreateHeader(&zfh)
	if err != nil {
		return nil, err
	}

	return &ZIPArchiveWriteCloser{w}, nil
}

func NewTARArchiveWriter(br io.Writer) (ArchiveWriter, error) {
	zw := tar.NewWriter(br)
	return &TARArchiveWriter{zw}, nil
}

func NewZipArchiveWriter(br io.Writer) (ArchiveWriter, error) {
	zw := zip.NewWriter(br)
	return &ZIPArchiveWriter{zw}, nil
}

func IsTAR(r io.ReadSeeker) (bool, error) {
	// get current pos
	c, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}

	block := [512]byte{}

	if _, err := r.Read(block[:]); err != nil {
		return false, err
	}

	// restore position
	_, err = r.Seek(c, io.SeekStart)
	return bytes.Compare(block[257:257+6], []byte("ustar\x00")) == 0, err
}

func IsExcluded(p string, l []string) bool {
	for _, g := range l {
		// we've checked the patterns before
		if matched, _ := path.Match(g, p); matched {
			return matched
		}
	}

	return false
}

func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	return fmt.Sprintf("%02dh:%02dm:%02ds", h, m, s)
}
