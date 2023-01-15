#pragma once
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include <set>
#include "gbf.h"
#include "util.h"
#include <unistd.h>

#include <fstream>

using namespace osuCrypto;

// for party 0->v-1
inline void user_encode(std::vector<block> inputSet, const std::vector<block> aesKeys, std::vector<block> &okvsTable, u64 party_t_id, u64 nParties, u64 type_okvs, u64 type_security)
{

	std::vector<block> setValues(inputSet.size(), ZeroBlock), hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(nParties);				   // but only use n-t -> n
	std::vector<std::vector<block>> ciphertexts(nParties); // ciphertexts[idxParty][idxItem], only use idxParty: n-t -> n

	for (u64 i = party_t_id; i < nParties; ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

	for (u64 i = party_t_id; i < nParties; ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); // compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
		for (u64 idxParty = party_t_id; idxParty < nParties; ++idxParty)
			setValues[idxItem] = setValues[idxItem] ^ ciphertexts[idxParty][idxItem];

	// std::cout << IoStream::lock;
	
	// for (u64 i = 0; i < inputSet.size(); i++)
	// 	std::cout << i << " : "<< inputSet[i] << " " << setValues[i] << std::endl;
	// std::cout << IoStream::unlock;

	if (type_okvs == SimulatedOkvs)
		SimulatedOkvsEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PolyOkvs)
		PolyEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PaxosOkvs)
		PaxosEncode(inputSet, setValues, okvsTable, 128);

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 2; i++)
	{
		std::cout << okvsTable[i] << " - okvsTable - " << i << std::endl;
	}
	std::cout << IoStream::unlock;*/

	// if (type_okvs == PolyOkvs) //TODO
	// std::vector<block> inputSet2PSI(inputSet.size(), ZeroBlock);
	// SimulatedOkvsDecode(okvsTable, inputSet, inputSet2PSI); //Decode(okvsTable, x) where okvsTable is received from party 1
	// std::cout << IoStream::lock;
	// for (u64 i = 0; i < 2; i++)
	//{
	//	std::cout << inputSet2PSI[i] << " - setValues decode party 1 - " << i << std::endl;
	// }
	// std::cout << IoStream::unlock;
}

inline void my_user_encode(std::vector<block>& inputSet, const std::vector<block>& aesKeys, std::vector<block> &okvsTable, block t, u64 party_t_id, u64 nParties, u64 type_okvs, u64 type_security)
{

	std::vector<block> setValues(inputSet.size(), t), hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(nParties);				   // but only use n-t -> n
	std::vector<std::vector<block>> ciphertexts(nParties); // ciphertexts[idxParty][idxItem], only use idxParty: n-t -> n

	for (u64 i = 0; i < party_t_id; ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

	for (u64 i = 0; i < party_t_id; ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); // compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
		for (u64 idxParty = 0; idxParty < party_t_id; ++idxParty)
			setValues[idxItem] = setValues[idxItem] ^ ciphertexts[idxParty][idxItem];

	// std::cout << IoStream::lock;
	
	// for (u64 i = 0; i < inputSet.size(); i++)
	// 	std::cout << i << " : "<< inputSet[i] << " " << setValues[i] << std::endl;
	// std::cout << IoStream::unlock;

	// std::cout << IoStream::lock;
	// for (u64 i = 0; i < 2; i++)
	//	std::cout << setValues[i] << " - encode party 1 - " << i << std::endl;
	// std::cout << IoStream::unlock;

	if (type_okvs == SimulatedOkvs)
		SimulatedOkvsEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PolyOkvs)
		PolyEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PaxosOkvs)
		PaxosEncode(inputSet, setValues, okvsTable, 128);

}

inline void my_user_encode_Pn(std::vector<block>& inputSet, const std::vector<block>& aesKeys, std::vector<block> &okvsTable, const std::vector<block>& randomValues, block t, u64 party_t_id, u64 nParties, u64 type_okvs, u64 type_security)
{

	std::vector<block> setValues(inputSet.size(), t), hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(nParties);				   // but only use n-t -> n
	std::vector<std::vector<block>> ciphertexts(nParties); // ciphertexts[idxParty][idxItem], only use idxParty: n-t -> n

	for (u64 i = 0; i < party_t_id; ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

	for (u64 i = 0; i < party_t_id; ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); // compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem) {
		setValues[idxItem] ^= randomValues[idxItem];
		for (u64 idxParty = 0; idxParty < party_t_id; ++idxParty)
			setValues[idxItem] ^=  ciphertexts[idxParty][idxItem];

	}
		

	// std::cout << IoStream::lock;
	
	// for (u64 i = 0; i < inputSet.size(); i++)
	// 	std::cout << i << " : "<< inputSet[i] << " " << setValues[i] << std::endl;
	// std::cout << IoStream::unlock;

	// std::cout << IoStream::lock;
	// for (u64 i = 0; i < 2; i++)
	//	std::cout << setValues[i] << " - encode party 1 - " << i << std::endl;
	// std::cout << IoStream::unlock;

	if (type_okvs == SimulatedOkvs)
		SimulatedOkvsEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PolyOkvs)
		PolyEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PaxosOkvs)
		PaxosEncode(inputSet, setValues, okvsTable, 128);

}



// for party t
inline void partyt_decode(const std::vector<block> inputSet, const std::vector<std::vector<block>> okvsTables, std::vector<block> &inputSet2ZeroXOR, u64 type_okvs, u64 type_security)
{
	inputSet2ZeroXOR.resize(inputSet.size(), ZeroBlock);
	std::vector<block> hashInputSet(inputSet.size());
	std::vector<block> decodeValues;

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

	for (u64 idxParty = 0; idxParty < okvsTables.size(); idxParty++)
	{
		if (type_okvs == SimulatedOkvs)
			SimulatedOkvsDecode(okvsTables[idxParty], hashInputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
		else if (type_okvs == PolyOkvs)
			PolyDecode(okvsTables[idxParty], hashInputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
		else if (type_okvs == PaxosOkvs)
			PaxosDecode(okvsTables[idxParty], hashInputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]

		for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
			inputSet2ZeroXOR[idxItem] = decodeValues[idxItem] ^ inputSet2ZeroXOR[idxItem]; // xor all values
	}

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 2; i++)
		std::cout << inputSet2PSI[i] << " - decode partyn - " << i << std::endl;
	std::cout << IoStream::unlock;*/

	// for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
	//	inputSet2PSI[idxItem] = inputSet2PSI[idxItem] ^ inputSet[idxItem]; //simulate x||F(x) xor all decodes
}

// for party t
inline void partyt_decode(std::vector<block> inputSet, const std::vector<block> okvsTable, std::vector<block> &decodeValues, u64 type_okvs, u64 type_security)
{
	decodeValues.resize(inputSet.size(), ZeroBlock);

	// for (u64 idxParty = 0; idxParty < okvsTables.size(); idxParty++)
	{
		if (type_okvs == SimulatedOkvs)
			SimulatedOkvsDecode(okvsTable, inputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
		else if (type_okvs == PolyOkvs)
			PolyDecode(okvsTable, inputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
		else if (type_okvs == PaxosOkvs)
			PaxosDecode(okvsTable, inputSet, decodeValues); // Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
	}

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 2; i++)
		std::cout << inputSet2PSI[i] << " - decode partyn - " << i << std::endl;
	std::cout << IoStream::unlock;*/

	// for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
	//	inputSet2PSI[idxItem] = inputSet2PSI[idxItem] ^ inputSet[idxItem]; //simulate x||F(x) xor all decodes
}

// for party t->n: compute XOR F(key_user, value)
inline void server_prf(const std::vector<block> inputSet, const std::vector<block> aesKeys, std::vector<block> &inputSet2ZeroXOR, u64 type_okvs, u64 type_security)
{
	inputSet2ZeroXOR.resize(inputSet.size(), ZeroBlock);
	std::vector<block> hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(aesKeys.size()); // but only use n-t -> n
	std::vector<std::vector<block>> ciphertexts(aesKeys.size());

	for (u64 i = 0; i < aesKeys.size(); ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

	for (u64 i = 0; i < aesKeys.size(); ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); // compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
		for (u64 idxParty = 0; idxParty < aesKeys.size(); ++idxParty)
			inputSet2ZeroXOR[idxItem] = inputSet2ZeroXOR[idxItem] ^ ciphertexts[idxParty][idxItem];
}

inline void tpsi_test(u64 type_okvs, u64 type_security)
{
	std::cout << " ============== party_test ==============\n";

	u64 nParties = 7, setSize = 32, intersection_size = 2;
	u64 threshold = 4;
	u64 party_t_id = nParties - threshold - 1;

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<std::vector<block>> inputSets(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		inputSets[i].resize(setSize);
		for (u64 j = 0; j < setSize; ++j)
			inputSets[i][j] = prng.get<block>();
	}

	for (u64 i = 1; i < nParties; ++i) // same items
		for (u64 j = 0; j < intersection_size; ++j)
			inputSets[i][j] = inputSets[0][j];

	// generating aes keys
	std::vector<block> aesKeys(nParties); // aesKeys[0] for party 2
	for (u64 i = 0; i < aesKeys.size(); ++i)
		aesKeys[i] = prng.get<block>();

	std::vector<std::vector<block>> okvsTables(party_t_id);

	std::vector<std::vector<block>> inputSet2ZeroXOR(nParties); // but only use [t--->n]

	for (u64 idxParty = 0; idxParty < party_t_id; ++idxParty) // user computes XOR of all F(k, value) and encodes them before sending to party_t
	{
		user_encode(inputSets[idxParty], aesKeys, okvsTables[idxParty], party_t_id, nParties, type_okvs, type_security);
	}

	partyt_decode(inputSets[party_t_id], okvsTables, inputSet2ZeroXOR[party_t_id], type_okvs, type_security);

	for (u64 idxParty = party_t_id + 1; idxParty < nParties; ++idxParty) // server
		server_prf(inputSets[idxParty], aesKeys, inputSet2ZeroXOR[idxParty], type_okvs, type_security);

	// check zeroXOR
	std::cout << " ============== check zeroXOR ==============\n";
	for (u64 i = 0; i < intersection_size * 2; ++i)
	{
		block checkZeroXOR = ZeroBlock;
		for (u64 idxParty = party_t_id; idxParty < nParties; ++idxParty) // server
			checkZeroXOR = checkZeroXOR ^ inputSet2ZeroXOR[idxParty][i];
		if (i < intersection_size)
			std::cout << checkZeroXOR << " -----------expected 0 \n";
		else
			std::cout << checkZeroXOR << " -----------expected !0 \n";
	}
	std::cout << " ============== done ==============\n";
}

inline void zeroXOR_party(u64 myIdx, u64 nPartiesZeroXor, u64 nParties, const std::vector<std::vector<Channel *>> chls, std::vector<block> inputSet, const std::vector<block> inputSet2ZeroXOR, std::vector<u64> &mIntersection, u64 type_okvs, u64 type_security)
{

	u64 chl_idx_shift = nParties - nPartiesZeroXor;

	u64 leaderIdx = nPartiesZeroXor - 1;
	u64 clientdx = 0; // one of them
	u64 setSize = inputSet.size();

	// Log::out << myIdx << "------send chls[" << leaderIdx + chl_idx_shift << "------" << Log::endl;

#pragma region setup
	u64 psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	int btCount = nPartiesZeroXor;

	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, myIdx)); // for test
																// set[0] = prng1.get<block>();;
	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));

#pragma endregion

	std::vector<block> sendPayLoads(setSize);
	std::vector<std::vector<block>> recvPayLoads(nPartiesZeroXor); // leader

	std::vector<KkrtNcoOtReceiver> otRecv(nPartiesZeroXor);
	std::vector<KkrtNcoOtSender> otSend(nPartiesZeroXor);

	OPPRFSender send;
	binSet bins;

	std::vector<OPPRFReceiver> recv(nPartiesZeroXor);
	std::vector<std::thread> pThrds(nPartiesZeroXor - 1);

	// Timer timer;

	//##########################
	//### Offline Phasing
	//##########################

	// auto start = timer.setTimePoint("start");
	PRNG prng_zs(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	// TODO(remove this hack: unconditional zero - sharing);
	// only one time => very mirror effect on perfomance
	std::vector<std::vector<block>> mSeeds(nPartiesZeroXor);

	for (u64 i = 0; i < nPartiesZeroXor; ++i)
	{
		mSeeds[i].resize(nPartiesZeroXor);
		for (u64 j = 0; j < nPartiesZeroXor; ++j)
		{
			if (i <= j)
				mSeeds[i][j] = prng_zs.get<block>();
			else
				mSeeds[i][j] = mSeeds[j][i];
		}
	}

	std::vector<PRNG> mSeedPrng(nPartiesZeroXor);
	for (u64 j = 0; j < nPartiesZeroXor; ++j)
	{
		mSeedPrng[j].SetSeed(mSeeds[myIdx][j]);
	}

	if (myIdx == leaderIdx) // leader
		for (u32 i = 0; i < recvPayLoads.size(); i++)
		{
			recvPayLoads[i].resize(setSize);
		}

	for (u64 i = 0; i < setSize; ++i)
	{
		sendPayLoads[i] = ZeroBlock;
		for (u64 pIdx = 0; pIdx < nPartiesZeroXor; pIdx++)
		{
			if (pIdx != myIdx)
				sendPayLoads[i] = sendPayLoads[i] ^ mSeedPrng[pIdx].get<block>();
		}
		sendPayLoads[i] = sendPayLoads[i] ^ inputSet2ZeroXOR[i]; // add zeroshare
		// sendPayLoads[i] =inputSet2ZeroXOR[i]; //add zeroshare
	}

	bins.init(myIdx, nPartiesZeroXor, setSize, psiSecParam, TableOPPRF, 1);
	u64 otCountSend = bins.mSimpleBins.mBins.size();
	u64 otCountRecv = bins.mCuckooBins.mBins.size();

	if (myIdx != leaderIdx)
	{

		/*std::cout << IoStream::lock;
			Log::out << myIdx << "------send --" <<leaderIdx << " chls[" << leaderIdx + chl_idx_shift << "------" << Log::endl;
		std::cout << IoStream::unlock;*/

		send.init(bins.mOpt, nPartiesZeroXor, setSize, psiSecParam, bitSize, chls[leaderIdx + chl_idx_shift], otCountSend, otSend[leaderIdx], otRecv[leaderIdx], prng.get<block>(), false);
	}
	else
	{

		std::vector<std::thread> pThrds(nPartiesZeroXor - 1);

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
					if (pIdx != leaderIdx)
					{

						/*std::cout << IoStream::lock;
						Log::out << pIdx << "------recv--" << leaderIdx << "  chls[" << pIdx + chl_idx_shift << "------" << Log::endl;
						std::cout << IoStream::unlock;*/

						recv[pIdx].init(bins.mOpt, nPartiesZeroXor, setSize, psiSecParam, bitSize, chls[pIdx + chl_idx_shift], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
					} });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}

	


	// auto initDone = timer.setTimePoint("initDone");

#ifdef PRINT
	std::cout << IoStream::lock;
	if (myIdx == leaderIdx)
	{
		Log::out << "------" << leaderIdx << "------" << Log::endl;
		Log::out << otRecv[pIdxTest].mGens[leaderIdx][0].get<block>() << Log::endl;
		Log::out << otRecv[pIdxTest].mGens[leaderIdx][1].get<block>() << Log::endl;
	}
	if (myIdx == pIdxTest)
	{
		Log::out << "------" << pIdxTest << "------" << Log::endl;
		Log::out << otSend[leaderIdx].mGens[0].get<block>() << Log::endl;
	}

	std::cout << IoStream::unlock;
#endif
    
	//##########################
	//### Hashing
	//##########################
	bins.hashing2Bins(inputSet, 1);
	// // bins.mSimpleBins.print(myIdx, true, false, false, false);
	// // bins.mCuckooBins.print(myIdx, true, false, false);

	// // auto hashingDone = timer.setTimePoint("hashingDone");

	// //##########################
	// //### Online Phasing - compute OPRF
	// //##########################

	if (myIdx == leaderIdx)
	{
		std::vector<std::thread> pThrds(nPartiesZeroXor - 1);

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
					if (pIdx != leaderIdx)
						recv[pIdx].getOPRFkeys(pIdx, bins, chls[pIdx + chl_idx_shift], false); });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}
	else
	{
		send.getOPRFkeys(leaderIdx, bins, chls[leaderIdx + chl_idx_shift], false);
	}

	

	// if (myIdx == leaderIdx)
	//{
	//	//bins.mSimpleBins.print(2, true, true, false, false);
	//	bins.mCuckooBins.print(1, true, true, false);
	//	Log::out << "------------" << Log::endl;
	// }
	// if (myIdx == 2)
	//{
	//	bins.mSimpleBins.print(leaderIdx, true, true, false, false);
	//	//bins.mCuckooBins.print(leaderIdx, true, true, false);
	// }

	// auto getOPRFDone = timer.setTimePoint("getOPRFDone");

	//##########################
	//### online phasing - secretsharing
	//##########################

	if (myIdx == leaderIdx)
	{

		if (!isNTLThreadSafe && (bins.mOpt == 1 || bins.mOpt == 2))
		{ // since NTL does not support thread safe => running in pipeline for poly-based-OPPRF
			for (u64 pIdx = 0; pIdx < nPartiesZeroXor - 1; ++pIdx)
			{
				if (pIdx != leaderIdx)
				{
					recv[pIdx].recvSS(pIdx, bins, recvPayLoads[pIdx], chls[pIdx + chl_idx_shift]);

					/*std::cout << IoStream::lock;
					Log::out << pIdx << "------recv[pIdx].recvSS-" << leaderIdx << "  recvPayLoads[" << recvPayLoads[pIdx][0] << "------" << Log::endl;
					std::cout << IoStream::unlock;*/
				}
			}
		}
		else
		{

			std::vector<std::thread> pThrds(nPartiesZeroXor - 1);
			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			{

				pThrds[pIdx] = std::thread([&, pIdx]()
										   {
						if (pIdx != leaderIdx)
							recv[pIdx].recvSS(pIdx, bins, recvPayLoads[pIdx], chls[pIdx + chl_idx_shift]); });
			}
			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();
		}
	}
	else
	{
		send.sendSS(leaderIdx, bins, sendPayLoads, chls[leaderIdx + chl_idx_shift]);

		/*std::cout << IoStream::lock;
		Log::out << myIdx << "------send.sendSS--" << leaderIdx << "  sendPayLoads[" << sendPayLoads[0] << "------" << Log::endl;
		std::cout << IoStream::unlock;*/
	}

	
	// auto getSSDone = timer.setTimePoint("secretsharingDone");

#ifdef PRINT
	std::cout << IoStream::lock;
	if (myIdx == leaderIdx)
	{
		// u64
		// block x0= set[bins.mCuckooBins.mBins[0].idx()];

		// for (int i = 0; i < 5; i++)
		{

			Log::out << myIdx << "r-5" << recvPayLoads[pIdxTest][5] << Log::endl;
			Log::out << myIdx << "r-4" << recvPayLoads[pIdxTest][4] << Log::endl;
			Log::out << myIdx << "r-13" << recvPayLoads[pIdxTest][13] << Log::endl;
		}
		Log::out << "------------" << Log::endl;
	}
	if (myIdx == pIdxTest)
	{
		// for (int i = 0; i < 5; i++)
		{
			// Log::out << recvPayLoads[i] << Log::endl;
			Log::out << myIdx << "s-5" << sendPayLoads[5] << Log::endl;
			Log::out << myIdx << "s-4" << sendPayLoads[4] << Log::endl;
			Log::out << myIdx << "s-13" << sendPayLoads[13] << Log::endl;
		}
	}

	std::cout << IoStream::unlock;
#endif

	//##########################
	//### online phasing - compute intersection
	//##########################

#if 1
	if (myIdx == leaderIdx)
	{

		for (u64 i = 0; i < setSize; ++i)
		{
			block sum = sendPayLoads[i];
			for (u64 pIdx = 0; pIdx < nPartiesZeroXor; pIdx++)
			{
				if (pIdx != myIdx)
				{
					// sum = sum ^ mSeedPrng[pIdx].get<block>();
					sum = sum ^ recvPayLoads[pIdx][i];
				}
			}

			/*if (i <3)
				std::cout << "sum " << sum << std::endl;*/

			if (!memcmp((u8 *)&sum, (u8 *)&ZeroBlock, bins.mMaskSize))
			{
				mIntersection.push_back(i);
			}
		}
		Log::out << "mIntersection.size(): " << mIntersection.size() << Log::endl;
	}
	// auto getIntersection = timer.setTimePoint("getIntersection");

	/*if (myIdx == clientdx || myIdx == leaderIdx) {

		if (myIdx == clientdx)
		{
			std::cout << "\nClient Idx: " << myIdx << "\n";
		}
		else
		{
			std::cout << "\nLeader Idx: " << myIdx << "\n";
		}

		if (myIdx == leaderIdx) {
			Log::out << "#Output Intersection: " << mIntersection.size() << Log::endl;
		}
	}*/

#endif
}

inline void channel_test(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 type_okvs, u64 type_security)
{

	u64 psiSecParam = 40, bitSize = 128, numChannelThreads = 1, okvsTableSize = setSize;
	u64 party_t_id = nParties - threshold;
	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties);
	std::vector<std::vector<Channel *>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;
			;												  // get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); // channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;				 // get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); // channel bwt i and pIdx, where i is receiver
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}

	if (myIdx < party_t_id) // user
	{
		for (u64 i = party_t_id + 1; i < nParties; ++i)
		{
			// char buffer[123];
			// sprintf(buffer, "%lu", myIdx);
			// aesSentKeys[i] = prng.get<block>(); //generating aes keys
			chls[i][0]->asyncSend(&myIdx, sizeof(myIdx)); // sending aesKeys[i] to party [t->n]

			// std::cout << IoStream::lock;
			// std::cout << aesSentKeys[i] << " - aesKeys[" << i << "] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
		}
	}

	else if (myIdx < nParties && myIdx > party_t_id) // server
	{
		for (u64 i = 0; i < party_t_id; ++i)
		{
			u64 s1 = 100;
			cout << s1 << endl;
			chls[i][0]->recv(&s1, sizeof(s1)); // party [t->n] receives aesKey from party [0->t-1]
			// std::cout << IoStream::lock;
			// std::cout << aesReceivedKeys[i] << " - aesReceivedKey[" <<i<<"] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
			cout << "myIdx:" << myIdx << ",get S:" << s1 << endl;
		}
	}

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();
}


inline void tpsi_zeroXOR_test(u64 type_okvs, u64 type_security)
{
	std::cout << " ============== party_test ==============\n";

	u64 nParties = 7, setSize = 32, intersection_size = 2;

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<std::vector<block>> inputSets(nParties);
	std::vector<std::vector<block>> inputSetZeroXOR(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		inputSets[i].resize(setSize);
		inputSetZeroXOR[i].resize(setSize);
		for (u64 j = 0; j < setSize; ++j)
		{
			inputSets[i][j] = prng.get<block>();
			inputSetZeroXOR[i][j] = prng.get<block>();
		}
	}

	for (u64 j = 0; j < intersection_size; ++j)
	{
		inputSetZeroXOR[0][j] = ZeroBlock;
		for (u64 i = 1; i < nParties; ++i) // same items
		{
			inputSets[i][j] = inputSets[0][j];
			inputSetZeroXOR[0][j] = inputSetZeroXOR[0][j] ^ inputSetZeroXOR[i][j];
		}
	}

	// std::string name("psi");
	// BtIOService ios(0);
	// std::vector < std::vector<BtEndpoint>> ep(nParties);
	// std::vector < std::vector<std::vector<Channel*>>> chls(nParties);

	// for (u64 myIdx = 0; myIdx < nParties; ++myIdx)
	//{
	//	ep[myIdx].resize(nParties);
	//	for (u64 i = 0; i < nParties; ++i)
	//	{
	//		if (i < myIdx)
	//		{
	//			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
	//			ep[myIdx][i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
	//		}
	//		else if (i > myIdx)
	//		{
	//			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
	//			ep[myIdx][i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
	//		}
	//	}

	//}

	// u64 numChannelThreads = 1;
	// for (u64 myIdx = 0; myIdx < nParties; ++myIdx)
	//	for (u64 i = 0; i < nParties; ++i)
	//	{
	//		if (i != myIdx) {
	//			chls[myIdx][i].resize(numChannelThreads);
	//			for (u64 j = 0; j < numChannelThreads; ++j)
	//				chls[myIdx][i][j] = &ep[myIdx][i].addChannel(name, name);
	//		}
	//	}

	std::vector<u64> mIntersection;
	std::vector<std::thread> pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]()
								   {
			//Channel_party_test(pIdx, nParties);
			//partyO1(pIdx, nParties, setSize, SimulatedOkvs, secSemiHonest);
		//	zeroXOR_party(pIdx, nParties, chls[pIdx], inputSets[pIdx], inputSetZeroXOR[pIdx], mIntersection, SimulatedOkvs, secSemiHonest);
			//partyO1(pIdx, nParties, setSize,PolyOkvs, secSemiHonest); 
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();
}


inline void tpsi_party(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 type_okvs, u64 type_security)
{
	// let v = n - t
	// party 0--->(v-1) distributes keys to central parties and generates OKVS for P_v
	// party v computes all XOR F(k,value)
	// party v+1 ---> n generates OKVS for P_v
	// setSize = 2^{12,16,20};
	u64 party_t_id = nParties - threshold - 1; // party who computes XOR of all F(key, value) from users
	// u64 num_users = party_t - 1; //party who sends each key to P_{i<v} and sends F(key, value) to P_v
	std::vector<u64> mIntersection; // store the intersection

	//std::fstream textout;
	//textout.open("./runtime_" + myIdx, textout.app | textout.out);

#pragma region setup
	u64 psiSecParam = 40, bitSize = 128, numChannelThreads = 1, okvsTableSize = setSize;
	u64 party_n = nParties - 1; // party n-1 
	Timer timer;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx)); // generate the size of expected_intersection 
	u64 expected_intersection = 3; // (*(u64*)&prng.get<block>()) % setSize;

	if (type_okvs == SimulatedOkvs)
		okvsTableSize = okvsLengthScale * setSize;
	else if (type_okvs == PolyOkvs)
		okvsTableSize = setSize;
	else if (type_okvs == PaxosOkvs)
		okvsTableSize = setSize;

	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties); 
	std::vector<std::vector<Channel *>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;
			;												  // get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); // channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;				 // get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); // channel bwt i and pIdx, where i is receiver
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}

	// generate the private set
	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
    // prngDiff is used to generate the unique elements related to myIdx
	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	std::vector<block> inputSet(setSize);

	for (u64 i = 0; i < expected_intersection; ++i)
		inputSet[i] = prngSame.get<block>();

	for (u64 i = expected_intersection; i < setSize; ++i)
		inputSet[i] = prngDiff.get<block>();

	// std::cout << IoStream::lock;
	
	// for (u64 i = 0; i < setSize; i++) {
	// 	std::cout << myIdx << " " << i << "  " << inputSet[i] << std::endl;
	// }
	// std::cout << IoStream::unlock;
	
#pragma endregion

	u64 num_threads = nParties - 1; // for party 1

	timer.reset();

	auto timer_start = timer.setTimePoint("start");

	std::vector<block> aesSentKeys(nParties);		// each users generates aes key. Indeed, we only use aesKeys[t->n]
	std::vector<block> aesReceivedKeys(party_t_id); // Indeed, we only use aesKeys[0->v-1]

	std::vector<block> sumXOR(setSize, ZeroBlock); 
	

	// prng_zs is used to generate the shares of zero
	PRNG prng_zs(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<std::vector<block> > zsShares(nParties);
	block t1 = ZeroBlock; // corresponding to T_i in the paper

	
	//==================================================
	//============sending and receiving aes keys========
	// Party $P_i$ for $i\in[1,v-1]$ chooses keys $\{k_{i,j}\}$ for $j\in[v+1,n]$ and sends $k_{i,j}$ to $P_j$
	if (myIdx < party_t_id) // user
	{
		for (u64 i = party_t_id + 1; i < nParties; ++i)
		{
			aesSentKeys[i] = prng.get<block>();					   // generating aes keys
			chls[i][0]->asyncSend(&aesSentKeys[i], sizeof(block)); // sending aesKeys[i] to party [v+1->n]

			// std::cout << IoStream::lock;
			// std::cout << aesSentKeys[i] << " - aesKeys[" << i << "] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
		}
	}

	else if (myIdx < nParties && myIdx > party_t_id) // server
	{
		for (u64 i = 0; i < party_t_id; ++i)
		{
			chls[i][0]->recv(&aesReceivedKeys[i], sizeof(block)); // party [v+1->n] receives aesKey from party [0->v-1]
			// std::cout << IoStream::lock;
			// std::cout << aesReceivedKeys[i] << " - aesReceivedKey[" <<i<<"] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
		}
	}

	// 
	//===============================================
	//============generate the shares of zero========

	// only one time => very mirror effect on perfomance
	if (myIdx > party_t_id && myIdx < nParties) {
		for (u64 i = 0; i < nParties; i++) {
			zsShares[i].resize(nParties);
			if (i <= party_t_id) continue;
			for (u64 j = 0; j < nParties; j++) {
				if (i <= j) 
					zsShares[i][j] = prng_zs.get<block>();
				else
					zsShares[i][j] = zsShares[j][i];
			}
		}

		for (int i = party_t_id + 1; i < nParties; i++) {
			if (i != myIdx)
				t1 ^= zsShares[myIdx][i];
		}
		// std::cout << IoStream::lock;
		// std::cout << myIdx << ":" << t1 << std::endl;
		// std::cout << IoStream::unlock;
		

		// std::cout << IoStream::unlock;

	}


	//check if the xorsum is zero
	// if (myIdx > party_t_id && myIdx < nParties - 1) {
	// 	chls[nParties - 1][0]->asyncSend(&t1, sizeof(block));
	// }

	// else if (myIdx == nParties - 1) {
	// 	std::vector<block> temp(threshold - 1);
	// 	for (u64 i = party_t_id + 1; i < nParties - 1; i++) {
			
	// 		chls[i][0]->recv(&temp[i - party_t_id - 1], sizeof(block));
	// 		t1 ^= temp[i - party_t_id - 1];
	// 	}

	// 	if (!memcmp((u8 *)&t1, (u8 *)&ZeroBlock, 16)) {
	// 		std::cout << IoStream::lock;
	// 		std::cout << "t1 == 0" << std::endl;
	// 		std::cout << IoStream::unlock;
	// 	}
	// }
	




	//====================================
	//============compute encoding========

	/*std::cout << IoStream::lock;
	std::cout << inputSet[0] << " - inputSet - " << myIdx  << std::endl;
	std::cout << IoStream::unlock;*/

	auto timer_asekey_done = timer.setTimePoint("asekey_done");
	
	if (myIdx < party_t_id) // user computes XOR of all F(k, value) and encodes them before sending to party P_v
	{
		std::vector<block> okvsTable; // okvs of group1
		user_encode(inputSet, aesSentKeys, okvsTable, party_t_id + 1, nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // sending okvsTable to party P_v
		//chls[party_t_id][0]->asyncSend(okvsTable.data(), okvsTable.size() * sizeof(block));
		

		auto timer_encode_done = timer.setTimePoint("distribute_done");

		/*	std::cout << IoStream::lock;
			for (u64 i = 0; i < okvsTable1.size(); i++)
				std::cout << okvsTable1[i] << " - " << i << "okvsTable1 gropu1_encode - " << myIdx << " ->" << party P_v << std::endl;
			std::cout << IoStream::unlock;*/
	}
    
	 if (myIdx > party_t_id && myIdx < nParties) {
		std::vector<block> okvsTable; // okvs of group2
		my_user_encode(inputSet, aesReceivedKeys, okvsTable, t1, party_t_id , nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // sending okvsTable to party P_v
		//chls[party_t_id][0]->asyncSend(okvsTable.data(), okvsTable.size() * sizeof(block));

		// std::cout << IoStream::lock;
		// std::cout << myIdx << ": " << okvsTable.size() * sizeof(block) << std::endl;
		// std::cout << IoStream::unlock;

		auto timer_encode_done = timer.setTimePoint("distribute_done");
	}

	//===================================================
	//============compute decoding and get answer========

	else if (myIdx == party_t_id) {

		std::vector<block> hashInputSet(inputSet.size());
		hashInputSet = inputSet;
		if (type_security == secMalicious)
			mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

		std::vector<std::vector<block> > okvsTables(nParties);
		std::vector<std::vector<block>> decOkvsTables(nParties);

		
		std::vector<std::thread> pThrds(nParties);
		
		for (u64 idxParty = 0; idxParty < pThrds.size(); ++idxParty)
		{
			if (idxParty == myIdx) continue;

			pThrds[idxParty] = std::thread([&, idxParty]()
											{
			okvsTables[idxParty].resize(okvsTableSize);
			chls[idxParty][0]->recv(okvsTables[idxParty].data(), okvsTables[idxParty].size() * sizeof(block)); //receving okvsTable from party 0->n-1 (expect v)
			partyt_decode(hashInputSet, okvsTables[idxParty], decOkvsTables[idxParty], type_okvs, type_security); });
			 
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
			if (pIdx == myIdx) continue;
			pThrds[pIdx].join();
		}
		// std::cout << IoStream::lock;
		// for (u64 i = 0; i < inputSet.size(); i++) {
		// 	std::cout << i << ":" << decOkvsTables[3][i] << std::endl;
		// }

		// std::cout << IoStream::unlock;
		

		for (u64 idxParty = 0; idxParty < nParties; ++idxParty)
		{
			if (idxParty == myIdx) continue;
			for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
				sumXOR[idxItem] ^= decOkvsTables[idxParty][idxItem]; // xor all values
		}
		// compute the size of intersection for correctness verification
		// u64 my_count = 0;
		// for (u64 i = 0; i < sumXOR.size(); i++) {

		// 	if (!memcmp((u8 *)&sumXOR[i], (u8 *)&ZeroBlock, 16)) {
		// 		std::cout << IoStream::lock;
		// 		std::cout << "inputSet " << i << ": " <<  inputSet[i] << std::endl;
		// 		std::cout << IoStream::unlock;
		// 		my_count++;
		// 	}
				
		// }

		// std::cout << IoStream::lock;

		// std::cout << "mycount:" <<  my_count << std::endl;

		// std::cout << IoStream::unlock;

		auto timer_encode_done = timer.setTimePoint("get_answer_done");		


	}
	


	double dataSent = 0, dataRecv = 0, Mbps = 0, MbpsRecv = 0;
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			// chls[i].resize(numThreads);
			// if (myIdx == nParties - 1 && i == party_t_id && threshold != nParties - 1)
			// {
			// 	// total communication cost is ~party_t(recv+sent) + (partyn-1)(recv+sent)
			// 	// the above calculation consists of 2x the comm cost btw party_t and partyn-1
			// 	//  Thus, we do nothing here
			// }
			// else
			{
				dataSent += chls[i][0]->getTotalDataSent();
				dataRecv += chls[i][0]->getTotalDataRecv();
			}
		}
	}

	    std::cout << IoStream::lock;
		std::cout << "party " << myIdx << " running time: \n";

		std::cout << timer << std::endl;
		std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
		std::cout << myIdx << " sends " << dataSent / std::pow(2.0, 20) << " MB and recieves " << dataRecv / std::pow(2.0, 20) << " MB" << std::endl;

		std::cout << IoStream::unlock;

	// if (myIdx == 0)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party " << myIdx << " running time: \n";

	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	// 	std::cout << IoStream::unlock;
	// }

	// if (myIdx == party_t_id)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party v running time: \n";
	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	// 	std::cout << IoStream::unlock;
	// }

	// if (myIdx == nParties - 1)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party " << myIdx << " running time: \n";
	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	// 	std::cout << IoStream::unlock;
	// }
	//}
	// else
	//{
	// if (myIdx == 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "Client running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	//	std::cout << IoStream::unlock;
	//}
	// if (myIdx == nParties - 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "last party running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << IoStream::unlock;
	//}

	// if (myIdx == 1)
	//	std::cout << "Total Comm: " << (((dataSent + dataRecv)*(nParties/2)) / std::pow(2.0, 20)) << " MB" << std::endl; //if t=n-1, total= each party*n/2

	//}/

	// total communication cost is ~party_t + (partyn-1)

	
	// close chanels
	
	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();
}


inline void tpsi_ca(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 type_okvs, u64 type_security)
{
	// let v = n - t
	// party 0--->(v-1) distributes key + value to central parties and generates OKVS for P_v
	// party v computes all XOR F(k,value)
	// party v+1 ---> n generates OKVS for P_v
	// setSize = 2^{12,16,20};
	u64 party_t_id = nParties - threshold - 1; // party who computes XOR of all F(key, value) from users
	// u64 num_users = party_t - 1; //party who sends each key to P_{i<v} and sends F(key, value) to P_v
	std::vector<u64> mIntersection;

	//std::fstream textout;
	//textout.open("./runtime_" + myIdx, textout.app | textout.out);

#pragma region setup
	u64 psiSecParam = 40, bitSize = 128, numChannelThreads = 1, okvsTableSize = setSize;
	u64 party_n = nParties - 1; // party n-1 vs n
	Timer timer;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx)); // generate the size of expected_intersection
	u64 expected_intersection = 3; // (*(u64*)&prng.get<block>()) % setSize;

	if (type_okvs == SimulatedOkvs)
		okvsTableSize = okvsLengthScale * setSize;
	else if (type_okvs == PolyOkvs)
		okvsTableSize = setSize;
	else if (type_okvs == PaxosOkvs)
		okvsTableSize = setSize;

	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties);
	std::vector<std::vector<Channel *>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;
			;												  // get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); // channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;				 // get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); // channel bwt i and pIdx, where i is receiver
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}

	// generate the private set
	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
    // prngDiff is used to generate the unique elements related to myIdx
	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	std::vector<block> inputSet(setSize);

	for (u64 i = 0; i < expected_intersection; ++i)
		inputSet[i] = prngSame.get<block>();

	for (u64 i = expected_intersection; i < setSize; ++i)
		inputSet[i] = prngDiff.get<block>();

	// std::cout << IoStream::lock;
	
	// for (u64 i = 0; i < setSize; i++) {
	// 	std::cout << myIdx << " " << i << "  " << inputSet[i] << std::endl;
	// }
	// std::cout << IoStream::unlock;
	
#pragma endregion

	u64 num_threads = nParties - 1; // for party 1

	timer.reset();

	auto timer_start = timer.setTimePoint("start");

	std::vector<block> aesSentKeys(nParties);		// each users generates aes key. Indeed, we only use aesKeys[t->n]
	std::vector<block> aesReceivedKeys(party_t_id); // Indeed, we only use aesKeys[0->v-1]

	 
	

	// prng_zs is used to generate the shares of zero
	PRNG prng_zs(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<std::vector<block> > zsShares(nParties);
	block t1 = ZeroBlock; // corresponding to T_i in the paper

	
	//==================================================
	//============sending and receiving aes keys========
	// Party $P_i$ for $i\in[1,v-1]$ chooses keys $\{k_{i,j}\}$ for $j\in[v+1,n]$ and sends $k_{i,j}$ to $P_j$
	if (myIdx < party_t_id) // user
	{
		for (u64 i = party_t_id + 1; i < nParties; ++i)
		{
			aesSentKeys[i] = prng.get<block>();					   // generating aes keys
			chls[i][0]->asyncSend(&aesSentKeys[i], sizeof(block)); // sending aesKeys[i] to party [v+1->n]

			// std::cout << IoStream::lock;
			// std::cout << aesSentKeys[i] << " - aesKeys[" << i << "] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
		}
	}

	else if (myIdx < nParties && myIdx > party_t_id) // server
	{
		for (u64 i = 0; i < party_t_id; ++i)
		{
			chls[i][0]->recv(&aesReceivedKeys[i], sizeof(block)); // party [v+1->n] receives aesKey from party [0->v-1]
			// std::cout << IoStream::lock;
			// std::cout << aesReceivedKeys[i] << " - aesReceivedKey[" <<i<<"] - myIdx" << myIdx << std::endl;
			// std::cout << IoStream::unlock;
		}
	}

	// 
	//===============================================
	//============generate the shares of zero========

	// only one time => very mirror effect on perfomance
	if (myIdx > party_t_id && myIdx < nParties) {
		for (u64 i = 0; i < nParties; i++) {
			zsShares[i].resize(nParties);
			if (i <= party_t_id) continue;
			for (u64 j = 0; j < nParties; j++) {
				if (i <= j) 
					zsShares[i][j] = prng_zs.get<block>();
				else
					zsShares[i][j] = zsShares[j][i];
			}
		}

		for (int i = party_t_id + 1; i < nParties; i++) {
			if (i != myIdx)
				t1 ^= zsShares[myIdx][i];
		}
		// std::cout << IoStream::lock;
		// std::cout << myIdx << ":" << t1 << std::endl;
		// std::cout << IoStream::unlock;
		

		// std::cout << IoStream::unlock;
	}


	//check if the xorsum is zero
	// if (myIdx > party_t_id && myIdx < nParties - 1) {
	// 	chls[nParties - 1][0]->asyncSend(&t1, sizeof(block));
	// }

	// else if (myIdx == nParties - 1) {
	// 	std::vector<block> temp(threshold - 1);
	// 	for (u64 i = party_t_id + 1; i < nParties - 1; i++) {
			
	// 		chls[i][0]->recv(&temp[i - party_t_id - 1], sizeof(block));
	// 		t1 ^= temp[i - party_t_id - 1];
	// 	}

	// 	if (!memcmp((u8 *)&t1, (u8 *)&ZeroBlock, 16)) {
	// 		std::cout << IoStream::lock;
	// 		std::cout << "t1 == 0" << std::endl;
	// 		std::cout << IoStream::unlock;
	// 	}
	// }


	//======================================================
	//============generate random values for P_n/P_1========
	
	
	std::vector<block> randomValues;
	if (myIdx == 0 || myIdx == nParties - 1) {
		PRNG prngR(_mm_set_epi32(4253465, 3434565, 23454, 876875));
		randomValues.resize(setSize);

		for (u64 i = 0; i < setSize; ++i)
		randomValues[i] = prngR.get<block>();

		// std::cout << IoStream::lock;
		// for (u64 i = 0; i < setSize; i++) {
		// 	std::cout << myIdx << " " << i << "  " << randomValues[i] << std::endl;
		// }
		// std::cout << IoStream::unlock;
	}
	




	//====================================
	//============compute encoding========

	/*std::cout << IoStream::lock;
	std::cout << inputSet[0] << " - inputSet - " << myIdx  << std::endl;
	std::cout << IoStream::unlock;*/

	auto timer_asekey_done = timer.setTimePoint("asekey_done");
	// 9.21 
	if (myIdx < party_t_id) // user computes XOR of all F(k, value) and encodes them before sending to party P_v
	{
		std::vector<block> okvsTable; // okvs of group1
		user_encode(inputSet, aesSentKeys, okvsTable, party_t_id + 1, nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // sending okvsTable to party P_v
		//chls[party_t_id][0]->asyncSend(okvsTable.data(), okvsTable.size() * sizeof(block));
		

		auto timer_encode_done = timer.setTimePoint("distribute_done");

		/*	std::cout << IoStream::lock;
			for (u64 i = 0; i < okvsTable1.size(); i++)
				std::cout << okvsTable1[i] << " - " << i << "okvsTable1 gropu1_encode - " << myIdx << " ->" << party P_v << std::endl;
			std::cout << IoStream::unlock;*/
	}
    
	else if (myIdx > party_t_id && myIdx < nParties - 1) {
		std::vector<block> okvsTable; // okvs of group2
		my_user_encode(inputSet, aesReceivedKeys, okvsTable, t1, party_t_id , nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // sending okvsTable to party P_v
		//chls[party_t_id][0]->asyncSend(okvsTable.data(), okvsTable.size() * sizeof(block));

		// std::cout << IoStream::lock;
		// std::cout << myIdx << ": " << okvsTable.size() * sizeof(block) << std::endl;
		// std::cout << IoStream::unlock;

		auto timer_encode_done = timer.setTimePoint("distribute_done");
	}

	//====================================
	//============compute decoding========

	else if (myIdx == nParties - 1) {
		std::vector<block> okvsTable; // okvs of group2
		my_user_encode_Pn(inputSet, aesReceivedKeys, okvsTable, randomValues, t1, party_t_id , nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); // sending okvsTable to party P_v
		//chls[party_t_id][0]->asyncSend(okvsTable.data(), okvsTable.size() * sizeof(block));

		// std::cout << IoStream::lock;
		// std::cout << myIdx << ": " << okvsTable.size() * sizeof(block) << std::endl;
		// std::cout << IoStream::unlock;

		auto timer_encode_done = timer.setTimePoint("distribute_done");
	}

	else if (myIdx == party_t_id) {
		std::vector<block> sumXOR(setSize, ZeroBlock);
		std::vector<block> hashInputSet(inputSet.size());
		hashInputSet = inputSet;
		if (type_security == secMalicious)
			mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); // H(xi)

		std::vector<std::vector<block> > okvsTables(nParties);
		std::vector<std::vector<block>> decOkvsTables(nParties);

		std::vector<std::thread> pThrds(nParties);
		for (u64 idxParty = 0; idxParty < pThrds.size(); ++idxParty)
		{
			if (idxParty == myIdx) continue;
			pThrds[idxParty] = std::thread([&, idxParty]()
											{
				okvsTables[idxParty].resize(okvsTableSize);
			chls[idxParty][0]->recv(okvsTables[idxParty].data(), okvsTables[idxParty].size() * sizeof(block)); //receving okvsTable from party 0->n-1 (expect v)
			partyt_decode(hashInputSet, okvsTables[idxParty], decOkvsTables[idxParty], type_okvs, type_security); });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
			if (pIdx == myIdx) continue;
			pThrds[pIdx].join();
		}

			


		// for (u64 idxParty = 0; idxParty < nParties; ++idxParty)
		// {
		// 	if (idxParty == myIdx) continue;
		// 	okvsTables[idxParty].resize(okvsTableSize);
		// 	chls[idxParty][0]->recv(okvsTables[idxParty].data(), okvsTables[idxParty].size() * sizeof(block)); //receving okvsTable from party 0->n-1 (expect v)
		// 	partyt_decode(hashInputSet, okvsTables[idxParty], decOkvsTables[idxParty], type_okvs, type_security); 
		// }
		// std::cout << IoStream::lock;
		// for (u64 i = 0; i < inputSet.size(); i++) {
		// 	std::cout << i << ":" << decOkvsTables[3][i] << std::endl;
		// }

		// std::cout << IoStream::unlock;
		

		for (u64 idxParty = 0; idxParty < nParties; ++idxParty)
		{
			if (idxParty == myIdx) continue;
			for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
				sumXOR[idxItem] ^= decOkvsTables[idxParty][idxItem]; // xor all values
		}

		auto timer_encode_done = timer.setTimePoint("get_randomValues_done");

		chls[0][0]->send(sumXOR.data(), sumXOR.size() * sizeof(block));

	}

    //====================================================
	//============get the intersection cardinality========

	if (myIdx == 0) {
		std::vector<block> tempValues(setSize);
		chls[party_t_id][0]->recv(tempValues.data(), tempValues.size() * sizeof(block));
		//compute the cardinality of the intersection
		u64 cardinality = 0;
		for (u64 i = 0; i < tempValues.size(); i++) {

			if (!memcmp((u8 *)&tempValues[i], (u8 *)&randomValues[i], 16)) {
				// std::cout << IoStream::lock;
				// std::cout << "tempValue " << i << ": " <<  tempValues[i] << std::endl;
				// std::cout << IoStream::unlock;
				cardinality++;
			}
				
		}

		// std::cout << IoStream::lock;

		// std::cout << "cardinality:" <<  cardinality << std::endl;

		// std::cout << IoStream::unlock;


		auto timer_encode_done = timer.setTimePoint("get_cardinality_done");

	}
	


	double dataSent = 0, dataRecv = 0, Mbps = 0, MbpsRecv = 0;
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			// chls[i].resize(numThreads);
			// if (myIdx == nParties - 1 && i == party_t_id && threshold != nParties - 1)
			// {
			// 	// total communication cost is ~party_t(recv+sent) + (partyn-1)(recv+sent)
			// 	// the above calculation consists of 2x the comm cost btw party_t and partyn-1
			// 	//  Thus, we do nothing here
			// }
			// else
			{
				dataSent += chls[i][0]->getTotalDataSent();
				dataRecv += chls[i][0]->getTotalDataRecv();
			}
		}
	}

	    std::cout << IoStream::lock;
		std::cout << "party " << myIdx << " running time: \n";

		std::cout << timer << std::endl;
		std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
		std::cout << myIdx << " sends " << dataSent / std::pow(2.0, 20) << " MB and recieves " << dataRecv / std::pow(2.0, 20) << " MB" << std::endl;

		std::cout << IoStream::unlock;

	// if (myIdx == 0)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party " << myIdx << " running time: \n";

	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	// 	std::cout << myIdx << " send " << dataSent / std::pow(2.0, 20) << " MB and recieve " << dataRecv / std::pow(2.0, 20) << " MB" << std::endl;

	// 	std::cout << IoStream::unlock;
	// }

	// if (myIdx == party_t_id)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party v running time: \n";
	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;

	// 	std::cout << myIdx << " send " << dataSent / std::pow(2.0, 20) << " MB and recieve " << dataRecv / std::pow(2.0, 20) << " MB" << std::endl;
	// 	std::cout << IoStream::unlock;
	// }

	// if (myIdx == nParties - 1)
	// {
	// 	std::cout << IoStream::lock;
	// 	std::cout << "party " << myIdx << " running time: \n";
	// 	std::cout << timer << std::endl;
	// 	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;

	// 	std::cout << myIdx << " send " << dataSent / std::pow(2.0, 20) << " MB and recieve " << dataRecv / std::pow(2.0, 20) << " MB" << std::endl;
	// 	std::cout << IoStream::unlock;
	// }
	//}
	// else
	//{
	// if (myIdx == 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "Client running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	//	std::cout << IoStream::unlock;
	//}
	// if (myIdx == nParties - 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "last party running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << IoStream::unlock;
	//}

	// if (myIdx == 1)
	//	std::cout << "Total Comm: " << (((dataSent + dataRecv)*(nParties/2)) / std::pow(2.0, 20)) << " MB" << std::endl; //if t=n-1, total= each party*n/2

	//}/

	// total communication cost is ~party_t + (partyn-1)

	
	// close chanels
	
	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();
}

